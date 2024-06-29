from django.db import models

class Dados(models.Model):
    IP = models.CharField(max_length=20)
    abuseipdb_is_whitelisted = models.CharField(max_length=5)
    abuseipdb_confidence_score = models.FloatField()
    abuseipdb_country_code = models.CharField(max_length=2)
    abuseipdb_isp = models.CharField(max_length=255)
    abuseipdb_domain = models.CharField(max_length=255)
    abuseipdb_total_reports = models.FloatField()
    abuseipdb_num_distinct_users = models.FloatField()
    abuseipdb_last_reported_at = models.DateTimeField()
    virustotal_reputation = models.FloatField()
    virustotal_regional_internet_registry = models.CharField(max_length=255)
    virustotal_as_owner = models.CharField(max_length=255)
    harmless = models.FloatField()
    malicious = models.FloatField()
    suspicious = models.FloatField()
    undetected = models.FloatField()
    IBM_score = models.FloatField()
    IBM_average_history_Score = models.FloatField()
    IBM_most_common_score = models.FloatField()
    virustotal_asn = models.CharField(max_length=255)
    SHODAN_asn = models.CharField(max_length=255)
    SHODAN_isp = models.CharField(max_length=255)
    ALIENVAULT_reputation = models.IntegerField()
    ALIENVAULT_asn = models.CharField(max_length=255)
    score_average_Mobat = models.FloatField()

    def __str__(self):
        return self.IP
