from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from main.models import UserProfile
from api.serializers import RegistrationSerializer

User = get_user_model()

class RegistrationMobileOptionalTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_registration_without_mobile_field(self):
        data = {
            "first_name": "John",
            "last_name": "Doe",
            "email": "johndoe@example.com",
        }
        response = self.client.post("/register/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(email="johndoe@example.com")
        profile = UserProfile.objects.get(user=user)
        self.assertIsNone(profile.mobile_number)

    def test_registration_with_empty_mobile(self):
        data = {
            "first_name": "Jane",
            "last_name": "Doe",
            "email": "janedoe@example.com",
            "mobile": ""
        }
        response = self.client.post("/register/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(email="janedoe@example.com")
        profile = UserProfile.objects.get(user=user)
        self.assertIsNone(profile.mobile_number)

    def test_multiple_registrations_without_mobile_succeed(self):
        data1 = {
            "first_name": "User",
            "last_name": "One",
            "email": "user1@example.com",
        }
        data2 = {
            "first_name": "User",
            "last_name": "Two",
            "email": "user2@example.com",
            "mobile": "",
        }
        resp1 = self.client.post("/register/", data1, format="json")
        resp2 = self.client.post("/register/", data2, format="json")
        self.assertEqual(resp1.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp2.status_code, status.HTTP_201_CREATED)

    def test_registration_with_valid_mobile(self):
        data = {
            "first_name": "Alice",
            "last_name": "Smith",
            "email": "alice@example.com",
            "mobile": "+1234567890"
        }
        response = self.client.post("/register/", data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(email="alice@example.com")
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.mobile_number, "+1234567890")

    def test_registration_with_duplicate_mobile_fails(self):
        data1 = {
            "first_name": "Bob",
            "last_name": "Smith",
            "email": "bob@example.com",
            "mobile": "+1987654321"
        }
        resp1 = self.client.post("/register/", data1, format="json")
        self.assertEqual(resp1.status_code, status.HTTP_201_CREATED)

        data2 = {
            "first_name": "Charlie",
            "last_name": "Brown",
            "email": "charlie@example.com",
            "mobile": "+1987654321"
        }
        resp2 = self.client.post("/register/", data2, format="json")
        self.assertEqual(resp2.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("mobile", resp2.data)
