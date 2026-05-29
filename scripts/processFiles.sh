#!/bin/bash

export ABUSEIPDB_API_KEY='@WAqpJi5C!qVMz2'
export MAXMIND_CITY_DB=/home/rdilley/temp/sensor_logs/GeoLite2-City_20250318/GeoLite2-City.mmdb
export MAXMIND_ASN_DB=/home/rdilley/temp/sensor_logs/GeoLite2-ASN_20250321/GeoLite2-ASN.mmdb

# Loop over all .gz files in the current directory
for file in *.gz; do
  # Skip if no .gz files found
  [ -e "$file" ] || continue

  # Strip .gz from filename to get base
  base="${file%.gz}"
  
  # Define output file
  outfile="${file}.out"

  echo "Processing $file -> $outfile"
  
  # Run the pipeline and capture output
  zcat "$file" | grep 'sensor:' | python3 sensor2json.py | python3 jsonAnalysis.py > "$outfile"
done
