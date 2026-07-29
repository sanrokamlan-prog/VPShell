/// <reference types="vite/client" />

interface VPShellLocalFontData {
  family: string;
  fullName: string;
  postscriptName: string;
  style: string;
}

interface Window {
  queryLocalFonts?: () => Promise<VPShellLocalFontData[]>;
}
