from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_module', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='ecdsa_public_key',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='user',
            name='encrypted_ecdsa_private_key',
            field=models.TextField(blank=True, default=''),
        ),
    ]
