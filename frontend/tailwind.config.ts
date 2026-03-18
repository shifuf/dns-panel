import type { Config } from 'tailwindcss';

export default {
  content: ['./index.html', './src/**/*.{vue,ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        panel: {
          bg: '#FAFAFA',
          surface: '#FFFFFF',
          elevated: '#F1F5F9',
          border: '#E2E8F0',
          'border-hover': '#CFDAE8',
        },
        accent: {
          DEFAULT: '#0052FF',
          hover: '#0047DE',
          dim: '#E9F0FF',
        },
        status: {
          success: '#16A34A',
          warning: '#B88336',
          error: '#DC2626',
          info: '#2563EB',
        },
      },
      fontFamily: {
        sans: ['Inter', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Consolas', 'monospace'],
        display: ['Calistoga', 'Georgia', 'serif'],
      },
    },
  },
  plugins: [],
} satisfies Config;
