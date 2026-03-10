class SNIExtractor:
    @staticmethod
    def extract_sni(payload: bytes):
        try:
            if len(payload) < 5:
                return None

            # TLS Handshake
            if payload[0] != 0x16:
                return None

            # Basic ClientHello check
            if len(payload) < 43:
                return None

            session_id_length = payload[43]
            offset = 44 + session_id_length

            if offset + 2 > len(payload):
                return None

            cipher_suites_length = int.from_bytes(payload[offset:offset + 2], "big")
            offset += 2 + cipher_suites_length

            if offset + 1 > len(payload):
                return None

            compression_methods_length = payload[offset]
            offset += 1 + compression_methods_length

            if offset + 2 > len(payload):
                return None

            extensions_length = int.from_bytes(payload[offset:offset + 2], "big")
            offset += 2
            end_extensions = offset + extensions_length

            while offset + 4 <= end_extensions and offset + 4 <= len(payload):
                ext_type = int.from_bytes(payload[offset:offset + 2], "big")
                ext_len = int.from_bytes(payload[offset + 2:offset + 4], "big")
                offset += 4

                if ext_type == 0x0000:
                    if offset + 5 > len(payload):
                        return None

                    sni_len = int.from_bytes(payload[offset + 3:offset + 5], "big")
                    sni_start = offset + 5
                    sni_end = sni_start + sni_len

                    if sni_end > len(payload):
                        return None

                    return payload[sni_start:sni_end].decode(errors="ignore")

                offset += ext_len

            return None

        except Exception:
            return None