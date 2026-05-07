from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('crypto_module', '0002_group_groupmember'),
    ]

    operations = [
        migrations.AddField(
            model_name='group',
            name='group_key',
            field=models.TextField(default=''),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='message',
            name='encrypted_key',
            field=models.TextField(blank=True, default=''),
        ),
    ]
