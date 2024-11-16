#!/bin/bash

# Define required variables
REQUIRED_VARS=("MASTER_KEY" "DB_PATH" "LOG_LEVEL" "PORT")

# Paths
ENV_FILE="/root/.env"
CONFIG_FILE="/root/config.yml"

# Create the .env file
echo "# Temporary Environment Variables" > $ENV_FILE

# Loop through required variables and check their presence
for VAR in "${REQUIRED_VARS[@]}"; do
  VALUE=$(printenv $VAR) # Get the variable's value
  if [ -z "$VALUE" ]; then
    echo "Error: $VAR is not set. Exiting."
    exit 1
  fi
  echo "$VAR=$VALUE" >> $ENV_FILE
done

# Write values to config.yaml
echo "Writing variables to config.yaml..."
cat <<EOL > $CONFIG_FILE
log_level: "$(printenv LOG_LEVEL)"
aes_key: "$(printenv MASTER_KEY)"
db_path: "$(printenv DB_PATH)"
port: "$(printenv PORT)"
EOL

# Clear the .env file for security
echo "Clearing temporary .env file..."
rm -f $ENV_FILE

echo "Environment variables successfully written to config.yml."
