import serial
import logging
import time

_LOGGER = logging.getLogger(__name__)

SYNC_TIMEOUT_S = 2.0
INTER_BYTE_TIMEOUT_S = 0.2

# LEN attendu par type de commande (nombre de bytes de données)
# PIA : 18 registres × 2 = 36 bytes = 0x24
# PIB : 26 registres × 2 = 52 bytes = 0x34
VALID_LEN_VALUES = (0x24, 0x34)


def expected_data_length(command_hex: str) -> int:
    """
    Retourne le LEN attendu dans la réponse à cette commande.
    LEN = count_registres × 2
    """
    try:
        raw = bytes.fromhex(command_hex)
        count = (raw[4] << 8) | raw[5]
        return count * 2   # LEN en bytes de données (sans addr/cmd/len/crc)
    except Exception:
        return 0


def read_modbus_response(ser, expected_addr: int, expected_data_len: int) -> bytes:
    """
    Lit une réponse Modbus RTU en cherchant spécifiquement la trame
    dont le LEN correspond à expected_data_len.

    Cela évite de confondre une réponse PIA (LEN=36) avec une PIB (LEN=52)
    quand les deux traînent dans le buffer.

    Phase 1 : byte par byte → trouve [expected_addr, 0x04]
    Phase 2 : lit LEN, vérifie = expected_data_len (sinon → faux positif, retry)
    Phase 3 : lit DATA (LEN bytes) + CRC (2 bytes)
    """
    deadline = time.monotonic() + SYNC_TIMEOUT_S

    while time.monotonic() < deadline:
        buf = bytearray()

        # Phase 1 : synchronisation sur [expected_addr, 0x04]
        synced = False
        while time.monotonic() < deadline:
            b = ser.read(1)
            if not b:
                continue
            byte_val = b[0]

            if len(buf) == 0:
                if byte_val == expected_addr:
                    buf.extend(b)
            elif len(buf) == 1:
                if byte_val == 0x04:
                    buf.extend(b)
                    synced = True
                    break
                else:
                    buf.clear()
                    if byte_val == expected_addr:
                        buf.extend(b)

        if not synced:
            _LOGGER.warning(
                "Sync : [0x%02X, 0x04] non trouvé en %ds",
                expected_addr, SYNC_TIMEOUT_S
            )
            return b""

        # Phase 2 : lire LEN et vérifier qu'il correspond à la commande envoyée
        len_byte = ser.read(1)
        if not len_byte:
            _LOGGER.warning("Timeout lecture LEN — retry")
            continue

        data_length = len_byte[0]

        if data_length not in VALID_LEN_VALUES:
            # Séquence [addr, 0x04] dans des données — faux positif
            _LOGGER.debug(
                "Faux positif : LEN=0x%02X non valide — retry sync", data_length
            )
            buf.clear()
            if data_length == expected_addr:
                buf.extend(len_byte)
            continue

        if data_length != expected_data_len:
            # C'est une vraie trame Modbus, mais pas celle qu'on attend.
            # Ex : on attend PIB (LEN=52) mais on lit PIA (LEN=36).
            # On jette cette trame entière et on recommence.
            _LOGGER.debug(
                "Trame LEN=0x%02X=%d ignorée (attendu LEN=0x%02X=%d) — "
                "lecture et rejet de la trame complète",
                data_length, data_length, expected_data_len, expected_data_len
            )
            # Lire et jeter le reste de cette trame (DATA + CRC)
            ser.read(data_length + 2)
            # Recommencer la synchro pour trouver la bonne trame
            continue

        buf.extend(len_byte)
        _LOGGER.debug(
            "Trame correcte : addr=0x%02X CMD=0x04 LEN=0x%02X (%d bytes)",
            expected_addr, data_length, data_length
        )

        # Phase 3 : lire DATA + CRC
        to_read = data_length + 2
        rest = ser.read(to_read)

        if len(rest) < to_read:
            _LOGGER.warning(
                "Trame incomplète : reçu %d bytes, attendu %d",
                len(rest), to_read
            )
            return b""

        buf.extend(rest)
        _LOGGER.debug("Trame complète (%d bytes) : %s", len(buf), buf.hex())
        return bytes(buf)

    _LOGGER.warning("Timeout global pour addr=0x%02X LEN=%d", expected_addr, expected_data_len)
    return b""


def send_serial_command(commands, port, baudrate=19200, timeout=2):
    """
    Envoie une liste de commandes Modbus RTU sur le port série et retourne
    les réponses sous forme de liste de chaînes hexadécimales.

    Gestion RS485 half-duplex :
    - reset_input_buffer() avant envoi
    - Consommation de l'écho (les bytes émis reviennent dans RX)
    - Synchronisation sur [addr, 0x04, LEN_attendu] pour ne lire
      que la trame correspondant à la commande envoyée
    """
    responses = []
    _LOGGER.debug("send_serial_command : commandes=%s port=%s", commands, port)

    try:
        with serial.Serial(
            port,
            baudrate=baudrate,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=INTER_BYTE_TIMEOUT_S,
        ) as ser:

            for command in commands:
                _LOGGER.debug("Envoi : %s", command)

                try:
                    cmd_bytes = bytes.fromhex(command)
                    expected_addr = cmd_bytes[0]
                except Exception:
                    _LOGGER.error("Commande invalide : %s", command)
                    responses.append("")
                    continue

                # LEN attendu dans la réponse à cette commande spécifique
                exp_data_len = expected_data_length(command)
                _LOGGER.debug(
                    "Commande addr=0x%02X, LEN réponse attendu=%d (0x%02X)",
                    expected_addr, exp_data_len, exp_data_len
                )

                # Vider le buffer
                ser.reset_input_buffer()

                # Envoyer la commande
                ser.write(cmd_bytes)

                # Consommer l'écho RS485 half-duplex
                # (les bytes émis reviennent dans le buffer RX)
                echo = ser.read(len(cmd_bytes))
                if len(echo) == len(cmd_bytes):
                    _LOGGER.debug("Écho RS485 consommé (%d bytes)", len(echo))
                else:
                    _LOGGER.debug(
                        "Écho partiel/absent (%d/%d bytes) — adaptateur supprime l'écho",
                        len(echo), len(cmd_bytes)
                    )

                # Lire la réponse en filtrant sur le bon LEN
                raw_response = read_modbus_response(ser, expected_addr, exp_data_len)

                if not raw_response:
                    _LOGGER.warning(
                        "Pas de réponse pour addr=0x%02X LEN=%d",
                        expected_addr, exp_data_len
                    )
                    responses.append("")
                    continue

                responses.append(raw_response.hex())
                _LOGGER.debug(
                    "Réponse OK addr=0x%02X LEN=%d (%d bytes total)",
                    expected_addr, exp_data_len, len(raw_response)
                )

                time.sleep(0.1)

    except serial.SerialException as e:
        _LOGGER.error("Erreur série sur %s : %s", port, e)
        return [""] * len(commands)

    _LOGGER.debug("Réponses finales : %s", responses)
    return responses
