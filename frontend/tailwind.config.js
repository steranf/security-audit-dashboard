/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                brand: {
                    blue: '#0056b3', // Example Innova-like blue
                    orange: '#ff6600', // Example Innova-like orange
                    dark: '#1a202c',
                    light: '#f7fafc',
                }
            }
        },
    },
    plugins: [],
}
