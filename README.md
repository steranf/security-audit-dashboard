Security Audit Dashboard



Este proyecto contiene el frontend de un panel de auditoría de seguridad. Está desarrollado con React + Vite + TailwindCSS.



🚀 Cómo empezar



Clonar el repositorio



git clone https://github.com/steranf/security-audit-dashboard.git

cd security-audit-dashboard/frontend



Instalar dependencias



npm install



Ejecutar en modo desarrollo



npm run dev



El servidor de desarrollo se abrirá en http://localhost:5173 (por defecto).



📂 Estructura del proyecto



src/ → Código fuente principal



App.jsx → Componente raíz



components/ → Componentes reutilizables (Header, Footer, Audits, ResultViewer)



api.js → Lógica para llamadas a la API



index.css → Estilos globales



main.jsx → Punto de entrada



package.json → Configuración de dependencias y scripts



vite.config.js → Configuración de Vite



tailwind.config.js → Configuración de TailwindCSS



⚙️ Recomendaciones



No subir node\_modules/: ya está ignorado en .gitignore.



Variables sensibles: usa un archivo .env para credenciales o configuraciones privadas.



Commits claros: describe brevemente los cambios realizados.



👥 Colaboración



Para traer los últimos cambios:



git pull origin main



Para subir tus cambios:



git add .

git commit -m "Descripción de los cambios"

git push origin main



📌 Notas



Este proyecto está en fase inicial. Se aceptan sugerencias y mejoras para optimizar el flujo de trabajo y la seguridad del dashboard.

