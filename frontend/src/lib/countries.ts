// ISO-3166 alpha-2 → name + centroid (lat, lng). Used only for globe placement.
// Centroids are approximate country centers; enough for a planetary-scale view.

export interface Country {
  name: string;
  lat: number;
  lng: number;
}

export const COUNTRIES: Record<string, Country> = {
  AE: { name: "United Arab Emirates", lat: 23.4, lng: 53.8 },
  AR: { name: "Argentina", lat: -38.4, lng: -63.6 },
  AT: { name: "Austria", lat: 47.5, lng: 14.6 },
  AU: { name: "Australia", lat: -25.3, lng: 133.8 },
  BD: { name: "Bangladesh", lat: 23.7, lng: 90.4 },
  BE: { name: "Belgium", lat: 50.5, lng: 4.5 },
  BG: { name: "Bulgaria", lat: 42.7, lng: 25.5 },
  BR: { name: "Brazil", lat: -14.2, lng: -51.9 },
  BY: { name: "Belarus", lat: 53.7, lng: 27.9 },
  CA: { name: "Canada", lat: 56.1, lng: -106.3 },
  CH: { name: "Switzerland", lat: 46.8, lng: 8.2 },
  CL: { name: "Chile", lat: -35.7, lng: -71.5 },
  CN: { name: "China", lat: 35.9, lng: 104.2 },
  CO: { name: "Colombia", lat: 4.6, lng: -74.3 },
  CZ: { name: "Czechia", lat: 49.8, lng: 15.5 },
  DE: { name: "Germany", lat: 51.2, lng: 10.5 },
  DK: { name: "Denmark", lat: 56.3, lng: 9.5 },
  EE: { name: "Estonia", lat: 58.6, lng: 25.0 },
  EG: { name: "Egypt", lat: 26.8, lng: 30.8 },
  ES: { name: "Spain", lat: 40.5, lng: -3.7 },
  FI: { name: "Finland", lat: 61.9, lng: 25.7 },
  FR: { name: "France", lat: 46.2, lng: 2.2 },
  GB: { name: "United Kingdom", lat: 55.4, lng: -3.4 },
  GR: { name: "Greece", lat: 39.1, lng: 21.8 },
  HK: { name: "Hong Kong", lat: 22.3, lng: 114.2 },
  HU: { name: "Hungary", lat: 47.2, lng: 19.5 },
  ID: { name: "Indonesia", lat: -0.8, lng: 113.9 },
  IE: { name: "Ireland", lat: 53.4, lng: -8.2 },
  IL: { name: "Israel", lat: 31.0, lng: 34.9 },
  IN: { name: "India", lat: 20.6, lng: 79.0 },
  IQ: { name: "Iraq", lat: 33.2, lng: 43.7 },
  IR: { name: "Iran", lat: 32.4, lng: 53.7 },
  IT: { name: "Italy", lat: 41.9, lng: 12.6 },
  JP: { name: "Japan", lat: 36.2, lng: 138.3 },
  KE: { name: "Kenya", lat: -0.02, lng: 37.9 },
  KP: { name: "North Korea", lat: 40.3, lng: 127.5 },
  KR: { name: "South Korea", lat: 35.9, lng: 127.8 },
  KZ: { name: "Kazakhstan", lat: 48.0, lng: 66.9 },
  LT: { name: "Lithuania", lat: 55.2, lng: 23.9 },
  LV: { name: "Latvia", lat: 56.9, lng: 24.6 },
  MD: { name: "Moldova", lat: 47.4, lng: 28.4 },
  MX: { name: "Mexico", lat: 23.6, lng: -102.6 },
  MY: { name: "Malaysia", lat: 4.2, lng: 102.0 },
  NG: { name: "Nigeria", lat: 9.1, lng: 8.7 },
  NL: { name: "Netherlands", lat: 52.1, lng: 5.3 },
  NO: { name: "Norway", lat: 60.5, lng: 8.5 },
  NZ: { name: "New Zealand", lat: -40.9, lng: 174.9 },
  PA: { name: "Panama", lat: 8.5, lng: -80.8 },
  PH: { name: "Philippines", lat: 12.9, lng: 121.8 },
  PK: { name: "Pakistan", lat: 30.4, lng: 69.3 },
  PL: { name: "Poland", lat: 51.9, lng: 19.1 },
  PT: { name: "Portugal", lat: 39.4, lng: -8.2 },
  RO: { name: "Romania", lat: 45.9, lng: 25.0 },
  RS: { name: "Serbia", lat: 44.0, lng: 21.0 },
  RU: { name: "Russia", lat: 61.5, lng: 105.3 },
  SA: { name: "Saudi Arabia", lat: 23.9, lng: 45.1 },
  SC: { name: "Seychelles", lat: -4.7, lng: 55.5 },
  SE: { name: "Sweden", lat: 60.1, lng: 18.6 },
  SG: { name: "Singapore", lat: 1.35, lng: 103.8 },
  TH: { name: "Thailand", lat: 15.9, lng: 101.0 },
  TR: { name: "Türkiye", lat: 39.0, lng: 35.2 },
  TW: { name: "Taiwan", lat: 23.7, lng: 121.0 },
  UA: { name: "Ukraine", lat: 48.4, lng: 31.2 },
  US: { name: "United States", lat: 37.1, lng: -95.7 },
  VN: { name: "Vietnam", lat: 14.1, lng: 108.3 },
  ZA: { name: "South Africa", lat: -30.6, lng: 22.9 },
};

export function countryName(code: string | null | undefined): string {
  if (!code) return "Unknown";
  return COUNTRIES[code.toUpperCase()]?.name ?? code.toUpperCase();
}

export function countryCoords(code: string | null | undefined): Country | null {
  if (!code) return null;
  return COUNTRIES[code.toUpperCase()] ?? null;
}
