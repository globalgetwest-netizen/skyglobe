import "./globals.css";
import Providers from "./providers";

export const metadata = {
  title: "Skyglobe",
  description: "Your Gateway to Travel & Study Abroad",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
