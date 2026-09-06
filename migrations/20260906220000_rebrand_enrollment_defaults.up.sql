-- Seed branded values before runtime defaults are initialized, and rebrand only
-- the recognizable upstream defaults. Customized enrollment content is left untouched.
UPDATE settings
SET enrollment_welcome_email_subject = 'S-Metric Secure: Welcome message after enrollment'
WHERE enrollment_welcome_email_subject IS NULL
   OR enrollment_welcome_email_subject = 'Defguard: Welcome message after enrollment';

UPDATE settings
SET enrollment_welcome_message = $smetric$
Dear {{ first_name }} {{ last_name }},

By completing the enrollment process, you now have access to all company systems.

Your login to all systems is: {{ username }}

## Company systems

- S-Metric Secure: {{ defguard_url }} - where you can change your password and manage your VPN devices

If you have any questions, contact your administrator.

The person that enrolled you is:
{{ admin_first_name }} {{ admin_last_name }},
email: {{ admin_email }}
mobile: {{ admin_phone }}

--
Sent by S-Metric Secure {{ defguard_version }}
$smetric$
WHERE enrollment_welcome_message IS NULL;

UPDATE settings
SET enrollment_welcome_email = $smetric$
Dear {{ first_name }} {{ last_name }},

By completing the enrollment process, you now have access to all company systems.

Your login to all systems is: {{ username }}

## Company systems

- S-Metric Secure: {{ defguard_url }} - where you can change your password and manage your VPN devices

If you have any questions, contact your administrator.

The person that enrolled you is:
{{ admin_first_name }} {{ admin_last_name }},
email: {{ admin_email }}
mobile: {{ admin_phone }}

--
Sent by S-Metric Secure {{ defguard_version }}
$smetric$
WHERE enrollment_welcome_email IS NULL;

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
