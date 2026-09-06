-- Roll back only values that still match the S-Metric defaults introduced by
-- the corresponding up migration. Customized content remains untouched.
UPDATE settings
SET enrollment_welcome_email_subject = 'Defguard: Welcome message after enrollment'
WHERE enrollment_welcome_email_subject = 'S-Metric Secure: Welcome message after enrollment';

UPDATE settings
SET enrollment_welcome_message = replace(
    replace(enrollment_welcome_message,
        '- S-Metric Secure: {{ defguard_url }} - where you can change your password and manage your VPN devices',
        '- Defguard: {{ defguard_url }} - where you can change your password and manage your VPN devices'),
    'Sent by S-Metric Secure {{ defguard_version }}',
    'Sent by Defguard {{ defguard_version }}')
WHERE enrollment_welcome_message LIKE '%Sent by S-Metric Secure {{ defguard_version }}%';

UPDATE settings
SET enrollment_welcome_email = replace(
    replace(enrollment_welcome_email,
        '- S-Metric Secure: {{ defguard_url }} - where you can change your password and manage your VPN devices',
        '- Defguard: {{ defguard_url }} - where you can change your password and manage your VPN devices'),
    'Sent by S-Metric Secure {{ defguard_version }}',
    'Sent by Defguard {{ defguard_version }}')
WHERE enrollment_welcome_email LIKE '%Sent by S-Metric Secure {{ defguard_version }}%';
