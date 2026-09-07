#!/bin/bash
echo ">>> Installing Flutter SDK in Vercel Container..."
git clone https://github.com/flutter/flutter.git -b stable --depth 1

# Add flutter to path
export PATH="$PATH:`pwd`/flutter/bin"

cd client

echo ">>> Injecting Environment Variables..."
if [ -z "$SUPABASE_URL" ]; then
  SUPABASE_URL="https://kyojroqhbvadzocdpnqn.supabase.co"
fi
if [ -z "$SUPABASE_ANON_KEY" ]; then
  SUPABASE_ANON_KEY="sb_publishable_trcpGuxjaKxTlb8Sa-b8vA_qWRPTwTf"
fi

echo "SUPABASE_URL=$SUPABASE_URL" > .env
echo "SUPABASE_ANON_KEY=$SUPABASE_ANON_KEY" >> .env
echo "DEVICE_UUID=web-agent" >> .env
echo "HIVE_ENCRYPTION_KEY_BASE64=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=" >> .env

echo ">>> Getting Packages..."
flutter pub get

echo ">>> Building Web Bundle..."
flutter build web --release

echo ">>> Build Complete!"
