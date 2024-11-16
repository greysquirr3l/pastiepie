#!/bin/bash

# Define required variables
REQUIRED_VARS=("MASTER_KEY" "DB_PATH" "LOG_LEVEL" "PORT")

# Paths
ENV_FILE="/root/.env"
CONFIG_FILE="/root/config.yml"

# Create the .env file
echo "# Temporary Environment Variables" > $ENV_FILE

echo "Checking required environment variables..."
for VAR in "${REQUIRED_VARS[@]}"; do
  VALUE=$(printenv $VAR) # Get the variable's value
  if [ -z "$VALUE" ]; then
    echo "Error: $VAR is not set. Exiting."
    exit 1
  fi
  echo "$VAR=$VALUE" >> $ENV_FILE
done

# Write values to config.yml
echo "Writing variables to $CONFIG_FILE..."
cat <<EOL > $CONFIG_FILE
log_level: "$(printenv LOG_LEVEL)"
aes_key: "$(printenv MASTER_KEY)"
db_path: "$(printenv DB_PATH)"  # Path is always quoted to handle spaces/special characters
port: "$(printenv PORT)"
EOL

# Check for errors in writing to config.yml
if [ $? -ne 0 ]; then
  echo "Error: Failed to write to $CONFIG_FILE. Exiting."
  exit 1
fi

# Clear the .env file for security
echo "Clearing temporary .env file..."
rm -f $ENV_FILE

# Check for errors in clearing .env
if [ $? -ne 0 ]; then
  echo "Warning: Failed to delete temporary .env file. Please remove it manually."
else
  echo "Temporary .env file cleared."
fi

echo "LOG_LEVEL value: $(printenv LOG_LEVEL)"
echo "DB_PATH value: $(printenv DB_PATH)"
echo "Environment variables successfully written to $CONFIG_FILE."
