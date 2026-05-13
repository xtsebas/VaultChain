from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('crypto_module', '0005_remove_group_group_key'),
    ]

    operations = [
        migrations.AddField(
            model_name='message',
            name='signature_verified',
            field=models.BooleanField(blank=True, default=None, null=True),
        ),
    ]
