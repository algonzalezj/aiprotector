# AI Protector 🛡️

## Descripción
AI Protector es una plataforma avanzada de ciberseguridad basada en Inteligencia Artificial diseñada para detectar amenazas mediante el análisis inteligente de logs en tiempo real. La aplicación permite identificar anomalías y comportamientos sospechosos, clasificándolos según su gravedad para facilitar una rápida respuesta y mitigación.

## Características Principales
- **Recepción y almacenamiento de logs mediante API**.
- **Análisis de logs con Machine Learning y Deep Learning**.
- **Alertas automáticas en tiempo real**.
- **Dashboard visual e interactivo** para monitorización.

## Instalación

### Clonar repositorio
```bash
git clone https://github.com/algonzalezj/aiprotector.git
cd ai_protector
```

### Crear entorno virtual
```bash
python3 -m venv venv
source venv/bin/activate  # Linux o MacOS
.\venv\Scripts\activate   # Windows
```

### Instalar dependencias
```bash
pip install -r requirements.txt
```

### Ejecutar la aplicación
```bash
python3 app.py
```

Accede al dashboard desde: `http://localhost:5000`

## Tecnologías Utilizadas
- Python
- Flask
- Elasticsearch
- Scikit-learn, TensorFlow
- AdminLTE

## Contribuir
¡Las contribuciones son bienvenidas!

1. Haz un fork del repositorio.
2. Crea tu rama de función: `git checkout -b feature/nueva-funcionalidad`
3. Realiza cambios y haz commit.
4. Envía una pull request para revisión.

## Licencia
Este proyecto está licenciado bajo la licencia **Apache 2.0**.


