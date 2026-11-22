export default {
  content: [
    "./index.html",
    "./src-frontend/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Selawik', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', 'sans-serif'],
      },
      colors: {
        ego: {
          blue: '#3B82F6',
          purple: '#8B5CF6',
          green: '#10B981',
          orange: '#F59E0B',
          red: '#EF4444',
        }
      }
    },
  },
  plugins: [],
}
