ALTER TABLE white_label_branding
    ADD COLUMN IF NOT EXISTS login_image_url TEXT NOT NULL DEFAULT '';
