@echo off
echo ================================
echo Instalador del Escaner de Red
echo ================================

:: Verificar si git está en el PATH
where git >nul 2>nul
if errorlevel 1 (
    echo ERROR: Git no está instalado o no está en el PATH.
    pause
    exit /b
)

:: Verificar si python está en el PATH
where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python no está instalado o no está en el PATH.
    pause
    exit /b
)

:: Clonar repositorio
echo Clonando repositorio...
git clone https://github.com/Francheskatap1a/mi-proyecto.git
cd mi-proyecto

:: Crear entorno virtual
echo Creando entorno virtual...
python -m venv venv

:: Activar entorno virtual
echo Activando entorno virtual...
call venv\Scripts\activate

:: Instalar dependencias
echo Instalando dependencias...
pip install --upgrade pip
pip install -r requerimientos.txt

:: Crear ejecutable
echo Generando ejecutable...
pyinstaller --onefile --noconsole Port_scan_archives\32.py

echo.
echo ================================
echo Instalación completada. El ejecutable está en la carpeta dist\
echo ================================
pause
