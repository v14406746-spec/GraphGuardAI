/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          dark: '#0B0F19',
          card: '#111827',
          surface: '#1E293B',
          border: '#1F2937',
          blue: '#3B82F6',
          cyan: '#06B6D4',
          emerald: '#10B981',
          amber: '#F59E0B',
          red: '#EF4444',
          purple: '#8B5CF6',
        }
      }
    },
  },
  plugins: [],
}
