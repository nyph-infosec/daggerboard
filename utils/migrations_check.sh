#!/bin/bash
check_result=`python manage.py makemigrations --check --dry-run`
echo $check_result
if [ "$check_result" == "No changes detected" ]
then
  echo "Migrations are up to date."
  exit 0
else
  echo "Changes requiring migrations detected."
  exit 1
fi
