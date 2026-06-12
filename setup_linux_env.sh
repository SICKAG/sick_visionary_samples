#!/usr/bin/env bash
set -euo pipefail

python3 -m venv .venv_sick_visionary_samples
source .venv_sick_visionary_samples/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

activate_cmd="source .venv_sick_visionary_samples/bin/activate"

echo -e "\033[32mSetup completed.\033[0m"
echo
echo -e "\033[33m============================================================\033[0m"
echo -e "\033[33m  ACTIVATE ENVIRONMENT WITH:\033[0m"
echo -e "\033[36m  ${activate_cmd}\033[0m"
echo -e "\033[33m============================================================\033[0m"
echo
