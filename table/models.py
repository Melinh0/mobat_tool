from django.db import models

class DataEntry(models.Model):
    IP = models.CharField(max_length=15)
    abuseipdb_is_whitelisted = models.BooleanField()
    abuseipdb_confidence_score = models.FloatField()
    abuseipdb_country_code = models.CharField(max_length=5)
    abuseipdb_isp = models.CharField(max_length=100)
    abuseipdb_domain = models.CharField(max_length=100)
    abuseipdb_total_reports = models.IntegerField()
    abuseipdb_num_distinct_users = models.IntegerField()
    abuseipdb_last_reported_at = models.DateTimeField()
    virustotal_reputation = models.IntegerField()
    virustotal_regional_internet_registry = models.CharField(max_length=100)
    virustotal_as_owner = models.CharField(max_length=100)
    harmless = models.IntegerField()
    malicious = models.IntegerField()
    suspicious = models.IntegerField()
    undetected = models.IntegerField()
    IBM_score = models.FloatField()
    IBM_average_history_Score = models.FloatField()
    IBM_most_common_score = models.FloatField()
    virustotal_asn = models.IntegerField()
    SHODAN_asn = models.IntegerField()
    SHODAN_isp = models.CharField(max_length=100)
    ALIENVAULT_reputation = models.IntegerField()
    ALIENVAULT_asn = models.IntegerField()
    score_average_Mobat = models.FloatField()

class Total(DataEntry):
    class Meta:
        db_table = 'Total'
