/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ops: {
          navy: '#070A12',
          panel: '#0B1020',
          purple: '#8B5CF6',
          lavender: '#A78BFA',
          amber: '#F59E0B'
        }
      },
      boxShadow: {
        soft: '0 20px 60px rgba(0, 0, 0, 0.22)',
        violet: '0 14px 34px rgba(139, 92, 246, 0.25)'
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace']
      }
    }
  },
  plugins: []
};
