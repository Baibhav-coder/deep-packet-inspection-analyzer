from dpi_types import AppType


class AppClassifier:
    @staticmethod
    def classify(parsed_packet, sni: str):
        if sni:
            sni = sni.lower().strip()

            # specific services first
            if "youtube" in sni or "youtu.be" in sni or "ytimg" in sni:
                return AppType.YOUTUBE

            if "google" in sni or "gstatic" in sni or "googleapis" in sni:
                return AppType.GOOGLE

            if "facebook" in sni or "fbcdn" in sni or "meta" in sni:
                return AppType.FACEBOOK

            if "instagram" in sni:
                return AppType.INSTAGRAM

            if "netflix" in sni or "nflx" in sni:
                return AppType.NETFLIX

            if "amazon" in sni or "amazonaws" in sni or "cloudfront" in sni:
                return AppType.AMAZON

            if "microsoft" in sni or "office" in sni or "outlook" in sni or "azure" in sni:
                return AppType.MICROSOFT

            if "apple" in sni or "icloud" in sni or "itunes" in sni:
                return AppType.APPLE

            if "whatsapp" in sni:
                return AppType.WHATSAPP

            if "telegram" in sni:
                return AppType.TELEGRAM

            if "tiktok" in sni or "musical.ly" in sni:
                return AppType.TIKTOK

            if "spotify" in sni:
                return AppType.SPOTIFY

            if "zoom" in sni:
                return AppType.ZOOM

            if "discord" in sni:
                return AppType.DISCORD

            if "github" in sni or "githubusercontent" in sni:
                return AppType.GITHUB

            if "cloudflare" in sni:
                return AppType.CLOUDFLARE

            # twitter/x must be checked carefully to avoid matching inside netflix.com
            if (
                "twitter.com" in sni
                or sni == "x.com"
                or sni.endswith(".x.com")
                or "twimg" in sni
            ):
                return AppType.TWITTER

            return AppType.HTTPS

        src_port = parsed_packet["src_port"]
        dst_port = parsed_packet["dst_port"]

        if src_port == 53 or dst_port == 53:
            return AppType.DNS

        if src_port == 80 or dst_port == 80:
            return AppType.HTTP

        if src_port == 443 or dst_port == 443:
            return AppType.HTTPS

        return AppType.UNKNOWN