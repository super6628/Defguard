-- Rebrand only the upstream default enrollment content. Customized enrollment
-- messages and subjects are intentionally left untouched.
UPDATE settings
SET enrollment_welcome_email_subject = 'S-Metric Secure: Welcome message after enrollment'
WHERE enrollment_welcome_email_subject = 'Defguard: Welcome message after enrollment';

UPDATE settings
SET enrollment_welcome_message = replace(
    replace(
        replace(enrollment_welcome_message,
            '- Defguard: {{ defguard_url }} - where you can change your password and manage your VPN devices',
            '- S-Metric Secure: {{ defguard_url }} - where you can change your password and manage your VPN devices'),
        'Sent by Defguard {{ defguard_version }}',
        'Sent by S-Metric Secure {{ defguard_version }}'),
    'Star us on GitHub! https://github.com/defguard/defguard',
    '')
WHERE enrollment_welcome_message LIKE '%Sent by Defguard {{ defguard_version }}%'
  AND enrollment_welcome_message LIKE '%Star us on GitHub! https://github.com/defguard/defguard%';

UPDATE settings
SET enrollment_welcome_email = replace(
    replace(
        replace(enrollment_welcome_email,
            '- Defguard: {{ defguard_url }} - where you can change your password and manage your VPN devices',
            '- S-Metric Secure: {{ defguard_url }} - where you can change your password and manage your VPN devices'),
        'Sent by Defguard {{ defguard_version }}',
        'Sent by S-Metric Secure {{ defguard_version }}'),
    'Star us on GitHub! https://github.com/defguard/defguard',
    '')
WHERE enrollment_welcome_email LIKE '%Sent by Defguard {{ defguard_version }}%'
  AND enrollment_welcome_email LIKE '%Star us on GitHub! https://github.com/defguard/defguard%';
