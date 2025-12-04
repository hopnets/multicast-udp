
sizes=(1 4 10 40 64 100 150 200 400 700 1000)

mkdir payloads

for sz in "${sizes[@]}"; do
    echo "Generating payload of size ${sz}MB..."
    ./build/gen_payload "$sz" "payloads/payload.bin_${sz}M"
done

echo "All payloads generated."
