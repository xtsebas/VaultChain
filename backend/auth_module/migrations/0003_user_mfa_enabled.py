from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_module', '0002_user_ecdsa_keys'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='mfa_enabled',
            field=models.BooleanField(default=False),
        ),
    ]
