/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class', // Controlled via adding/removing 'dark' on <html>
  content: [
    "./templates/**/*.html",
    "./static/**/*.js"
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Space Grotesk"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      colors: {
        canvas: 'var(--bg-canvas)',
        surface: 'var(--bg-surface)',
        'surface-subtle': 'var(--bg-surface-subtle)',
        boundary: 'var(--border-color)',
        content: {
          primary: 'var(--text-primary)',
          secondary: 'var(--text-secondary)',
          muted: 'var(--text-muted)',
        },
        brand: {
          accent: 'var(--accent-primary)',
          'accent-text': 'var(--accent-primary-text)',
          cyber: 'var(--accent-secondary)',
        },
        severity: {
          critical: 'var(--color-critical)',
          high: 'var(--color-high)',
          medium: 'var(--color-medium)',
          low: 'var(--color-low)',
          clean: 'var(--color-clean)',
        }
      },
      borderWidth: {
        '2': '2px',
        '1.5': '1.5px',
      }
    }
  }
}
