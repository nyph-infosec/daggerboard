#!/bin/bash

# This script automates the installation and setup of the Daggerboard project.
# It performs the following tasks:
# - Creates necessary directories with appropriate ownership and permissions
# - Installs required packages and dependencies
# - Sets up a Python virtual environment and installs the required Python packages
# - Configures and starts the RabbitMQ server
# - Configures and starts the Celery service
# - Runs Django migrations and creates a superuser
# - Collects static files and compresses them
# - Sets up logging and database files with proper permissions

# Exits immediately if a command exits with a non-zero status
set -e

# Variables
PROJECT_DIR="/var/www/Daggerboard/"
SOURCE_DIR=$(pwd)
APP_USER=daggerboard
APP_GROUP=daggerboard
ENVIRONMENT="development"
VENV_DIR="$PROJECT_DIR/venv"
REQUIREMENTS_FILE="$PROJECT_DIR/requirements.txt"
UPLOAD_DIR="$PROJECT_DIR/apps/sbomscanner/uploads"
UPLOAD_SBOM_DIR="$PROJECT_DIR/apps/sbomscanner/uploads/sbom"
LOG_DIR="$PROJECT_DIR/logs"
INSTALL_LOG="$SOURCE_DIR/install.log"
LOG_FILE="$PROJECT_DIR/logs/sbom.log"
ARCHIVE_DIR="$PROJECT_DIR/apps/sbomscanner/archive_spdx"
CELERY_LOG_FILE="$PROJECT_DIR/logs/celery.log"
ENV_SETTINGS="$PROJECT_DIR/.env"
DB_DIR="$PROJECT_DIR/db"
DB_FILE="$PROJECT_DIR/db/db.sqlite3"
CELERY_DB_FILE="$PROJECT_DIR/db/tasks.sqlite"
PYTHON_VERSION="/usr/bin/python3.10"
SUPERUSER_USERNAME="admin"
SUPERUSER_EMAIL="admin@example.com"
SUPERUSER_PASSWORD="ships&blades2024"
HOSTNAME=$(hostname)

# Function to log messages
log() {
    echo "$(date '+%Y-%M-%d %H:%M:%S') - $1" | tee -a "$INSTALL_LOG"
}

# Create the group if it doesn't exist
if ! getent group "$APP_GROUP" > /dev/null; then
    sudo groupadd "$APP_GROUP"
fi

# Create the user if it doesn't exist
if ! id -u "$APP_USER" > /dev/null 2>&1; then
    sudo useradd -g "$APP_GROUP" "$APP_USER"
fi

# Ensure install.log is owned by daggerboard user and group
sudo chown "$APP_USER:$APP_GROUP" "$INSTALL_LOG"

# Function to handle errors
error_handler() {
    local exit_code=$?
    local line_number=${BASH_LINENO[0]}
    log "Error occurred in script at line: $line_number"
    log "Exit code: $exit_code"
    exit $exit_code
}

# Trap errors and call the error_handler function
trap 'error_handler' ERR

# Function to create directories with proper ownership and permissions
create_dir() {
    local dir=$1
    local owner=$2
    local permissions=$3
    if [ ! -d "$dir" ]; then
        sudo mkdir -p "$dir"
        sudo chown "$owner" "$dir"
        sudo chmod "$permissions" "$dir"
    else
        log "$dir already exists."
    fi
}

# Function to install a package if not already installed
install_package() {
    local package=$1
    if ! dpkg -l | grep -q "$package"; then
        sudo apt-get install -y "$package"
    else
        log "$package is already installed."
    fi
}

# Start installation
log "Starting installation of Daggerboard..."

# Create the group if it doesn't exist
if ! getent group "$APP_GROUP" >/dev/null; then
    log "Creating group $APP_GROUP..."
    sudo groupadd "$APP_GROUP"
fi

# Create the user if it doesn't exist
if ! id -u "$APP_USER" >/dev/null 2>&1; then
    log "Creating user $APP_USER..."
    sudo useradd -m -g "$APP_GROUP" -s /bin/bash "$APP_USER"
fi

# Ensure /var/www directory exists
if [ ! -d "/var/www" ]; then
    sudo mkdir -p /var/www
    sudo chown "$APP_USER:$APP_GROUP" /var/www
fi

# Move the directory if necessary
if [ "$SOURCE_DIR" != "$PROJECT_DIR" ]; then
    log "Moving directory to $PROJECT_DIR as $APP_USER..."
    sudo rsync -a --chown=$APP_USER:$APP_GROUP "$SOURCE_DIR/" "$PROJECT_DIR/"
fi

# Set environment variable for Django settings module
export DJANGO_SETTINGS_MODULE="daggerboardproject.settings.$ENVIRONMENT"

# Update package list
log "Updating package list..."
sudo apt-get update

# Install necessary packages
log "Installing necessary packages..."
install_package "python3"
install_package "python3-pip"
install_package "python3-venv"
install_package "libldap2-dev"
install_package "libsasl2-dev"
install_package "rabbitmq-server"

# Install Celery
log "Installing Celery..."
pip3 install celery

# Create necessary directories
log "Creating necessary directories..."
create_dir "$LOG_DIR" "$APP_USER:$APP_GROUP" "755"
create_dir "$UPLOAD_SBOM_DIR" "$APP_USER:$APP_GROUP" "775"
create_dir "$UPLOAD_DIR" "$APP_USER:$APP_GROUP" "777"
create_dir "$ARCHIVE_DIR" "$APP_USER:$APP_GROUP" "755"
create_dir "$PROJECT_DIR/apps/sbomscanner/nvdrepo" "$APP_USER:$APP_GROUP" "755"
create_dir "$DB_DIR" "$APP_USER:$APP_GROUP" "775"
create_dir "$PROJECT_DIR/run" "$APP_USER:$APP_GROUP" "755"


# Create and set permissions for log files
log "Creating and setting permissions for log files..."
sudo touch "$LOG_FILE" "$CELERY_LOG_FILE"
sudo chown $APP_USER:$APP_GROUP "$LOG_FILE" "$CELERY_LOG_FILE"
sudo chmod g+w "$LOG_FILE" "$CELERY_LOG_FILE"

# Create and set permissions for database files
log "Creating and setting permissions for database files..."
sudo touch "$DB_FILE" "$CELERY_DB_FILE"
sudo chown $APP_USER:$APP_GROUP "$DB_FILE" "$CELERY_DB_FILE"
sudo chmod gou+w "$DB_FILE" "$CELERY_DB_FILE"

# Create virtual environment and install requirements
log "Creating virtual environment and installing..."
sudo -u "$APP_USER" python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Set pip install
log "Setting pip configuration..."
pip install -r "$REQUIREMENTS_FILE"

# Ensure the directory structure exists
log "Creating directory structure for logs..."
mkdir -p "$PROJECT_DIR/logs"

# Create the sbom.log file
log "Creating sbom.log file..."
touch "$LOG_FILE"

# Set permissions for the sbom.log file
log "Setting permissions for sbom.log file..."
chown $APP_USER:$APP_GROUP "$LOG_FILE"
chmod 664 "$LOG_FILE"

# Activate the virtual environment
source "$VENV_DIR/bin/activate"

# Collect static files
log "Collecting static files..."
"$VENV_DIR/bin/python" "$PROJECT_DIR/manage.py" collectstatic --noinput
"$VENV_DIR/bin/python" "$PROJECT_DIR/manage.py" compress --follow-links --extension=html

sudo chown -R $APP_USER:$APP_GROUP "$PROJECT_DIR" "apps/daggerboard_ui/static"

# Run Django migrations and create superuser
log "Running Django migrations and creating superuser..."
"$VENV_DIR/bin/python" "$PROJECT_DIR/manage.py" makemigrations
"$VENV_DIR/bin/python" "$PROJECT_DIR/manage.py" migrate

SUPERUSER_CREATION_SCRIPT=$(cat <<EOF
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='$SUPERUSER_USERNAME').exists():
    User.objects.create_superuser('$SUPERUSER_USERNAME', '$SUPERUSER_EMAIL', '$SUPERUSER_PASSWORD')
else:
    print('Superuser already exists.')
EOF
)
echo "$SUPERUSER_CREATION_SCRIPT" | sudo -u "$APP_USER" "$VENV_DIR/bin/python" "$PROJECT_DIR/manage.py" shell

# Create GradeWeights and GradeThresholds
log "Creating GradeWeights and GradeThresholds..."
GRADEWEIGHTS_CREATION_SCRIPT=$(cat <<EOF
from apps.grading.models import GradeWeights
if not GradeWeights.objects.filter(id=1).exists():
    GradeWeights.objects.create(id=1, crit_weight=40, high_weight=10, medium_weight=3, low_weight=1)
else:
    print('GradeWeights entry already exists.')
EOF
)
echo "$GRADEWEIGHTS_CREATION_SCRIPT" | sudo -u "$APP_USER" "$VENV_DIR/bin/python" "$PROJECT_DIR/manage.py" shell

log "Creating GradeWeights and GradeThresholds..."
GRADETHRESHOLDS_CREATION_SCRIPT=$(cat <<EOF
from apps.grading.models import GradeThresholds
if not GradeThresholds.objects.filter(id=1).exists():
    GradeThresholds.objects.create(
        id=1,
        less_than_threshold_grade_A=2,
        greater_eq_threshold_grade_B=2,
        less_than_threshold_grade_B=4,
        greater_eq_threshold_grade_C=4,
        less_than_threshold_grade_C=6,
        greater_eq_threshold_grade_D=6,
        less_than_threshold_grade_D=8,
        greater_eq_threshold_grade_F=8
    )
else:
    print('GradeThresholds entry already exists.')
EOF
)
echo "$GRADETHRESHOLDS_CREATION_SCRIPT" | sudo -u "$APP_USER" "$VENV_DIR/bin/python" "$PROJECT_DIR/manage.py" shell

# Enable and start RabbitMQ service
log "Enabling and starting RabbitMQ service..."
sudo rabbitmq-plugins enable rabbitmq_management
sudo systemctl enable rabbitmq-server
sudo systemctl start rabbitmq-server

# Create directories for Celery
log "Creating directories for Celery..."
create_dir "/var/www/Daggerboard/run/celery" "$APP_USER:$APP_GROUP" "755"

# Create environment file for Celery
log "Creating environment file for Celery..."
sudo tee /etc/default/celery > /dev/null <<EOF
CELERYD_NODES="worker"
CELERY_BIN="/var/www/Daggerboard/venv/bin/celery"
CELERY_APP="daggerboardproject.celery"
CELERYD_MULTI="multi"
CELERYD_OPTS="--time-limit=300 --concurrency=8"
CELERYD_LOG_LEVEL="INFO"
CELERYD_LOG_FILE="/var/www/Daggerboard/logs/celery.log"
CELERYD_PID_FILE="/var/www/Daggerboard/run/celery/%n.pid"
DJANGO_SETTINGS_MODULE="daggerboardproject.settings.$ENVIRONMENT"
EOF

# Create systemd service file for Celery
log "Creating systemd service file for Celery..."
sudo tee /etc/systemd/system/celery.service > /dev/null <<EOF
[Unit]
Description=Celery Service
After=network.target

[Service]
Type=forking
User=$APP_USER
Group=$APP_GROUP
EnvironmentFile=/etc/default/celery
WorkingDirectory=/var/www/Daggerboard
ExecStart=/var/www/Daggerboard/venv/bin/celery -A daggerboardproject.settings.celery multi start worker --loglevel=info --logfile=/var/www/Daggerboard/logs/celery.log --pidfile=/var/www/Daggerboard/run/celery/%n.pid
ExecStop=/var/www/Daggerboard/venv/bin/celery multi stopwait worker --pidfile=/var/www/Daggerboard/run/celery/%n.pid
ExecReload=/bin/kill -s HUP \$MAINPID

[Install]
WantedBy=multi-user.target
EOF

log "Fetching NVD data"
sudo -u $APP_USER $PROJECT_DIR/apps/sbomscanner/get_nvd_data_feed $PROJECT_DIR/apps/sbomscanner $APP_USER

# Reload systemd, enable and start Celery service
log "Reloading systemd, enabling and starting Celery service..."
sudo systemctl daemon-reload
sudo systemctl enable celery.service
sudo systemctl restart celery.service


log "Installation completed successfully!"
echo ""
echo "=============================================================="
echo " Daggerboard installation and setup are complete!"
echo "=============================================================="
echo ""
echo "To start the Daggerboard development server, run the following commands:"
echo ""
echo "sudo -u daggerboard -s <<EOF"
echo "cd $PROJECT_DIR"
echo "source $VENV_DIR/bin/activate"
echo "python manage.py runserver 0.0.0.0:8000"
echo "EOF"
echo ""