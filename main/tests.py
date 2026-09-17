from django.test import TestCase, Client

class AppAdsTxtTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_app_ads_txt(self):
        response = self.client.get('/app-ads.txt')
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response['Content-Type'])
        self.assertIn("google.com, pub-8492413081634752, DIRECT, f08c47fec0942fa0", response.content.decode('utf-8'))

    def test_ads_txt(self):
        response = self.client.get('/ads.txt')
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response['Content-Type'])
        self.assertIn("google.com, pub-8492413081634752, DIRECT, f08c47fec0942fa0", response.content.decode('utf-8'))
