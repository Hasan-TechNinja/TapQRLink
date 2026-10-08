from django.test import TestCase, Client

class AppAdsTxtTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_app_ads_txt(self):
        response = self.client.get('/app-ads.txt')
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response['Content-Type'])
        self.assertIn("google.com, pub-8492413081634752, DIRECT, f08c47fec0942fa0", response.content.decode('utf-8'))

        response_slash = self.client.get('/app-ads.txt/')
        self.assertEqual(response_slash.status_code, 200)
        self.assertIn("text/plain", response_slash['Content-Type'])
        self.assertIn("google.com, pub-8492413081634752, DIRECT, f08c47fec0942fa0", response_slash.content.decode('utf-8'))

    def test_ads_txt(self):
        response = self.client.get('/ads.txt')
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response['Content-Type'])
        self.assertIn("google.com, pub-8492413081634752, DIRECT, f08c47fec0942fa0", response.content.decode('utf-8'))

        response_slash = self.client.get('/ads.txt/')
        self.assertEqual(response_slash.status_code, 200)
        self.assertIn("text/plain", response_slash['Content-Type'])
        self.assertIn("google.com, pub-8492413081634752, DIRECT, f08c47fec0942fa0", response_slash.content.decode('utf-8'))


class LegalPagesTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_privacy_policy_page(self):
        response = self.client.get('/privacy-policy/')
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'privacy_policy.html')
        self.assertTemplateUsed(response, 'base.html')
        self.assertContains(response, 'Privacy Policy')
        self.assertContains(response, 'TapQRLink')
        self.assertContains(response, 'Camera & Permissions')

    def test_privacy_alias_page(self):
        response = self.client.get('/privacy/')
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'privacy_policy.html')

    def test_terms_and_conditions_page(self):
        response = self.client.get('/terms-and-conditions/')
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'terms_and_conditions.html')
        self.assertTemplateUsed(response, 'base.html')
        self.assertContains(response, 'Terms & Conditions')
        self.assertContains(response, 'Acceptance of Terms')

    def test_terms_aliases_pages(self):
        for route in ['/terms/', '/terms-of-service/']:
            response = self.client.get(route)
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, 'terms_and_conditions.html')


