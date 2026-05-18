#!/usr/bin/env sh
DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$DIR/gradle/wrapper/gradle-wrapper.jar" ]; then
  exec java -jar "$DIR/gradle/wrapper/gradle-wrapper.jar" "$@"
else
  echo "Gradle wrapper JAR not found. Run 'gradle wrapper' on a machine with Gradle to generate the wrapper."
  exit 1
fi
