from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db.models.fields.related import OneToOneField
# from .models import Userprofile
from django.contrib.auth.models import User
from django.db.models.signals import post_save,pre_save
from django.dispatch import receiver
    


class UserManager(BaseUserManager):
    def create_user(self,first_name,username,last_name,email,password=None):
        if not email:
            raise ValueError('User must have email address')
        if  not username:
            raise ValueError('User must have an username')

        user=self.model(
        email=self.normalize_email(email),
        username=username,
        first_name=first_name,
        last_name=last_name
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self,first_name,username,last_name,email,password=None):
        user=self.create_user(
            email=self.normalize_email(email),
            username=username,
            password=password,
            first_name=first_name,
            last_name=last_name

        )

        user.is_admin=True
        user.is_active=True
        user.is_staff=True
        user.is_superadmin=True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    VENDOR=1
    CUSTOMER=2

    ROLE_CHOICE={
        (VENDOR, 'Vendor'),
        (CUSTOMER,'Customer'),
    }
    first_name=models.CharField(max_length=50)
    last_name=models.CharField(max_length=50)
    username=models.CharField(max_length=50,unique=True)
    email=models.EmailField(max_length=50,unique=True)
    phone_number=models.CharField(max_length=12,blank=True)
    role=models.PositiveIntegerField(choices=ROLE_CHOICE,blank=True,null =True)

    # required fields
    date_joined=models.DateTimeField(auto_now_add=True)
    last_login=models.DateTimeField(auto_now_add=True)
    created_date=models.DateTimeField(auto_now_add=True)
    modified_date=models.DateTimeField(auto_now=True)
    is_admin=models.BooleanField(default=False)
    is_staff=models.BooleanField(default=False)
    is_active=models.BooleanField(default=False)
    is_superadmin=models.BooleanField(default=False)


    USERNAME_FIELD='email'
    REQUIRED_FIELDS=['username','first_name','last_name']

    objects=UserManager()

    def __str__(self):
        return self.email

    def has_perm(self,perm,obj=None):
        return self.is_admin
    

    def has_module_perms(self,app_label):
        return True

    def get_role(self):
        # user_role = None
        if self.role==1:
            user_role='Vendor'
        elif self.role==2:
            user_role='Customer'
        # else:
            # user_role='undefined'
        return user_role


    #required fields are

    # date_joined=models.DateTimeField(auto_now_add=True)


class UserProfile(models.Model):
    user=OneToOneField(User,on_delete=models.CASCADE,blank=True,null=True)
    profile_picture=models.ImageField(upload_to='users/profile_pictures,blank=True,null =true')
    cover_photo=models.ImageField(upload_to='users/cover_photos',blank=True,null=True)
    address=models.CharField(max_length=250,blank=True,null=True)
    country= models.CharField(max_length=50,blank=True,null=True)
    state=models.CharField(max_length=50,blank=True,null=True)
    city=models.CharField(max_length=50,blank=True,null=True)
    pincode=models.CharField(max_length=6,blank=True,null=True)
    latitude=models.CharField(max_length=20,blank=True,null=True)
    longitude=models.CharField(max_length=20,blank=True,null=True)
    created_at=models.DateTimeField(auto_now_add=True)
    modified_at=models.DateTimeField(auto_now=True)


    # def full_address(self):
    #     return f'{self.address_line_1},{self.address_line_2}'


    def __str__(self):
        return self.user.email

# @receiver(post_save, sender=User)
# def post_save_create_profile_receiver(sender,instance,created,**kwargs):
#     if created:
#         UserProfile.objects.create(user=instance)
#         print("create the user profile")

#     else:
#         try:
#             profile=UserProfile.objects.get(user=instance)
#             profile.save()
#         except:
#             UserProfile.objects.create(user=instance)
            
# @receiver(pre_save,sender=User)
# def pre_save_profile_receiver(sender,instance,**kwargs):
#     print(instance.username,"this is being saved")

# post_save_connect(post_save,create_profile,receiver,sender=User)


    



# Create your models here.
