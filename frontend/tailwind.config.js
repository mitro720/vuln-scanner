/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                primary: {
                    50: '#f5f3ff',
                    100: '#ede9fe',
                    200: '#ddd6fe',
                    300: '#c4b5fd',
                    400: '#a78bfa',
                    500: '#8b5cf6', // Main neon purple
                    600: '#7c3aed',
                    700: '#6d28d9',
                    800: '#5b21b6',
                    900: '#4c1d95',
                },
                severity: {
                    critical: '#f43f5e', // Rose 500
                    high: '#f97316',     // Orange 500
                    medium: '#fbbf24',   // Amber 400
                    low: '#a855f7',      // Purple 500
                    info: '#38bdf8',     // Sky 400
                },
                slate: {
                    950: '#020617',
                    900: '#0f172a',
                    800: '#1e293b',
                    700: '#334155',
                },
                dark: {
                    bg: '#020617',      // Deep slate background
                    surface: '#0f172a', // Card surface
                    surface2: '#1e293b', // Hover surface
                    border: 'rgba(255, 255, 255, 0.05)',
                    text: '#f8fafc',
                    'text-secondary': '#94a3b8',
                }
            },
            fontFamily: {
              sans: ['Inter', 'sans-serif'],
              mono: ['JetBrains Mono', 'monospace'],
            },
            animation: {
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'scan': 'scan 2s linear infinite',
                'shimmer': 'shimmer 2s linear infinite',
                'float': 'float 6s ease-in-out infinite',
            },
            keyframes: {
                scan: {
                    '0%': { transform: 'translateX(-100%)' },
                    '100%': { transform: 'translateX(100%)' },
                },
                shimmer: {
                    '100%': { transform: 'translateX(100%)' },
                },
                float: {
                    '0%, 100%': { transform: 'translateY(0)' },
                    '50%': { transform: 'translateY(-10px)' },
                }
            },
            backgroundImage: {
                'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
                'gradient-primary': 'radial-gradient(circle at 50% 50%, #0f172a 0%, #020617 100%)',
                'gradient-accent': 'linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)',
                'glass-gradient': 'linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0) 100%)',
            },
            boxShadow: {
              'neon': '0 0 15px rgba(139, 92, 246, 0.3)',
              'neon-strong': '0 0 25px rgba(139, 92, 246, 0.5)',
              'inner-glass': 'inset 0 1px 1px rgba(255, 255, 255, 0.05)',
            }
        },
    },
    plugins: [
        require('@tailwindcss/typography'),
        require('tailwind-scrollbar'),
    ],
}
