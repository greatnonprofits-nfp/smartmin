import random
import string
import requests

import phonenumbers

from datetime import timedelta

from django import forms
from django.conf import settings
from django.contrib import messages, auth
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.views import LoginView
from django.core.mail import send_mail
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.template import loader
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django.views.generic import TemplateView

from smartmin.email import build_email_context
from smartmin.views import SmartCRUDL, SmartView, SmartFormView, SmartListView, SmartCreateView, SmartUpdateView
from .models import RecoveryToken, PasswordHistory, FailedLogin, is_password_complex

from temba.channels.views import ALL_COUNTRIES, COUNTRY_CALLING_CODES


class UserForm(forms.ModelForm):
    new_password = forms.CharField(label=_("New Password"), widget=forms.PasswordInput, strip=False)
    groups = forms.ModelMultipleChoiceField(widget=forms.CheckboxSelectMultiple,
                                            queryset=Group.objects.all(), required=False)

    def clean_new_password(self):
        password = self.cleaned_data['new_password']

        # if they specified a new password
        if password and not is_password_complex(password):
            raise forms.ValidationError(_("Passwords must have at least 8 characters, including one uppercase, "
                                          "one lowercase and one number"))

        return password

    def save(self, commit=True):
        """
        Overloaded so we can save any new password that is included.
        """
        is_new_user = self.instance.pk is None

        user = super(UserForm, self).save(commit)

        # new users should be made active by default
        if is_new_user:
            user.is_active = True

        # if we had a new password set, use it
        new_pass = self.cleaned_data['new_password']
        if new_pass:
            user.set_password(new_pass)
            if commit:
                user.save()

        return user

    class Meta:
        model = get_user_model()
        fields = ('username', 'new_password', 'first_name', 'last_name', 'email', 'groups', 'is_active')


class UserUpdateForm(UserForm):
    new_password = forms.CharField(label=_("New Password"), widget=forms.PasswordInput, required=False, strip=False)

    tel = forms.CharField(label=_("Phone Number"), max_length=16, required=False)

    authy_id = forms.CharField(label=_("Authy ID"), max_length=100, required=False)

    def clean_new_password(self):
        password = self.cleaned_data['new_password']

        if password and not is_password_complex(password):
            raise forms.ValidationError(_("Passwords must have at least 8 characters, including one uppercase, "
                                          "one lowercase and one number"))

        if password and PasswordHistory.is_password_repeat(self.instance, password):
            raise forms.ValidationError(_("You have used this password before in the past year, "
                                          "please use a new password."))

        return password


class UserProfileForm(UserForm):
    old_password = forms.CharField(label=_("Password"), widget=forms.PasswordInput, required=False, strip=False)
    new_password = forms.CharField(label=_("New Password"), widget=forms.PasswordInput, required=False, strip=False)
    confirm_new_password = forms.CharField(
        label=_("Confirm Password"), widget=forms.PasswordInput, required=False, strip=False
    )

    def clean_old_password(self):
        user = self.instance

        if(not user.check_password(self.cleaned_data['old_password'])):
            raise forms.ValidationError(_("Please enter your password to save changes."))

        return self.cleaned_data['old_password']

    def clean_confirm_new_password(self):
        if 'new_password' not in self.cleaned_data:
            return None

        if not self.cleaned_data['confirm_new_password'] and self.cleaned_data['new_password']:
            raise forms.ValidationError(_("Confirm the new password by filling the this field"))

        if self.cleaned_data['new_password'] != self.cleaned_data['confirm_new_password']:
            raise forms.ValidationError(_("New password doesn't match with its confirmation"))

        password = self.cleaned_data['new_password']
        if password and not is_password_complex(password):
            raise forms.ValidationError(_("Passwords must have at least 8 characters, including one uppercase, "
                                          "one lowercase and one number"))

        if password and PasswordHistory.is_password_repeat(self.instance, password):
            raise forms.ValidationError(_("You have used this password before in the past year, "
                                          "please use a new password."))

        return self.cleaned_data['new_password']


class UserForgetForm(forms.Form):
    email = forms.EmailField(label=_("Your Email"),)

    def clean_email(self):
        email = self.cleaned_data['email'].strip()

        allow_email_recovery = getattr(settings, 'USER_ALLOW_EMAIL_RECOVERY', True)
        if not allow_email_recovery:
            raise forms.ValidationError(_("E-mail recovery is not supported, "
                                          "please contact the website administrator to reset your password manually."))

        return email


class SetPasswordForm(UserForm):
    old_password = forms.CharField(label=_("Current Password"), widget=forms.PasswordInput, required=True, strip=False,
                                   help_text=_("Your current password"))
    new_password = forms.CharField(label=_("New Password"), widget=forms.PasswordInput, required=True,
                                   help_text=_("Your new password."), strip=False)
    confirm_new_password = forms.CharField(label=_("Confirm new Password"), widget=forms.PasswordInput, required=True,
                                           help_text=_("Confirm your new password."), strip=False)

    def clean_old_password(self):
        user = self.instance
        if not user.check_password(self.cleaned_data['old_password']):
            raise forms.ValidationError(_("Please enter your password to save changes"))

        return self.cleaned_data['old_password']

    def clean_confirm_new_password(self):
        if 'new_password' not in self.cleaned_data:
            return None

        if not self.cleaned_data['confirm_new_password'] and self.cleaned_data['new_password']:
            raise forms.ValidationError(_("Confirm your new password by entering it here"))

        if self.cleaned_data['new_password'] != self.cleaned_data['confirm_new_password']:
            raise forms.ValidationError(_("Mismatch between your new password and confirmation, try again"))

        password = self.cleaned_data['new_password']
        if password and not is_password_complex(password):
            raise forms.ValidationError(_("Passwords must have at least 8 characters, including one uppercase, "
                                          "one lowercase and one number"))

        if password and PasswordHistory.is_password_repeat(self.instance, password):
            raise forms.ValidationError(_("You have used this password before in the past year, "
                                          "please use a new password."))

        return self.cleaned_data['new_password']


class UserCRUDL(SmartCRUDL):
    model = get_user_model()
    permissions = True
    actions = ('create', 'list', 'update', 'profile', 'forget', 'recover', 'expired', 'failed', 'newpassword', 'mimic')

    class List(SmartListView):
        search_fields = ('username__icontains', 'first_name__icontains', 'last_name__icontains')
        fields = ('username', 'name', 'group', 'last_login')
        link_fields = ('username', 'name')
        default_order = 'username'
        add_button = True
        template_name = "smartmin/users/user_list.html"

        def get_context_data(self, **kwargs):
            context = super(UserCRUDL.List, self).get_context_data(**kwargs)
            context['groups'] = Group.objects.all()
            group_id = self.request.POST.get('group_id', self.request.GET.get('group_id', 0))
            context['group_id'] = int(group_id)
            return context

        def get_group(self, obj):
            return ", ".join([group.name for group in obj.groups.all()])

        def get_queryset(self, **kwargs):
            queryset = super(UserCRUDL.List, self).get_queryset(**kwargs)
            group_id = self.request.POST.get('group_id', self.request.GET.get('group_id', 0))
            group_id = int(group_id)

            # filter by the group
            if group_id:
                queryset = queryset.filter(groups=group_id)

            # ignore superusers and staff users
            return queryset.exclude(is_staff=True).exclude(is_superuser=True).exclude(password=None)

        def get_name(self, obj):
            return obj.get_full_name()

    class Create(SmartCreateView):
        form_class = UserForm
        fields = ('username', 'new_password', 'first_name', 'last_name', 'email', 'groups')
        success_message = _("New user created successfully.")

        field_config = {
            'groups': dict(label=_("Groups"),
                           help=_("Users will only get those permissions that are allowed for their group.")),
            'new_password': dict(label=_("Password"), help=_("Set the user's initial password here.")),
        }

        def post_save(self, obj):
            """
            Make sure our groups are up to date
            """
            if 'groups' in self.form.cleaned_data:
                for group in self.form.cleaned_data['groups']:
                    obj.groups.add(group)

            return obj

    class Update(SmartUpdateView):
        template_name = "smartmin/users/user_update.html"
        success_message = "User saved successfully."
        fields = ('username', 'new_password', 'first_name', 'last_name', 'email', 'tel', 'authy_id', 'groups',
                  'is_active', 'last_login')
        field_config = {
            'last_login': dict(readonly=True, label=_("Last Login")),
            'is_active': dict(label=_("Is Active"), help=_("Whether this user is allowed to log into the site")),
            'groups': dict(label=_("Groups"),
                           help=_("Users will only get those permissions that are allowed for their group")),
            'new_password': dict(label=_("New Password"),
                                 help=_("You can reset the user's password by entering a new password here")),
        }

        def get_form_class(self):
            form = UserUpdateForm
            user = self.object
            user_settings = get_user_model().get_settings(user)
            form.base_fields['tel'].initial = user_settings.tel
            form.base_fields['authy_id'].initial = user_settings.authy_id
            return form

        def post_save(self, obj):
            """
            Make sure our groups are up to date
            """
            if 'groups' in self.form.cleaned_data:
                obj.groups.clear()
                for group in self.form.cleaned_data['groups']:
                    obj.groups.add(group)

            # if a new password was set, reset our failed logins
            if 'new_password' in self.form.cleaned_data and self.form.cleaned_data['new_password']:
                FailedLogin.objects.filter(user=self.object).delete()
                PasswordHistory.objects.create(user=obj, password=obj.password)

            if 'tel' in self.form.cleaned_data or 'authy_id' in self.form.cleaned_data:
                user_settings = get_user_model().get_settings(self.object)
                user_settings.tel = self.form.cleaned_data['tel']
                user_settings.authy_id = self.form.cleaned_data['authy_id']
                user_settings.save(update_fields=['tel', 'authy_id'])

            return obj

    class Profile(SmartUpdateView):
        form_class = UserProfileForm
        success_message = "User profile saved successfully."
        fields = ('username', 'old_password', 'new_password', 'confirm_new_password',
                  'first_name', 'last_name', 'email')
        field_config = {
            'username': dict(readonly=True, label=_("Username")),
            'old_password': dict(label=_("Password"), help=_("Your password")),
            'new_password': dict(label=_("New Password"), help=_("If you want to set a new password, enter it here")),
            'confirm_new_password': dict(label=_("Confirm New Password"), help=_("Confirm your new password")),
        }

        def post_save(self, obj):
            obj = super(UserCRUDL.Profile, self).post_save(obj)
            if 'new_password' in self.form.cleaned_data and self.form.cleaned_data['new_password']:
                FailedLogin.objects.filter(user=self.object).delete()
                PasswordHistory.objects.create(user=obj, password=obj.password)

            return obj

        def get_object(self, queryset=None):
            return self.request.user

        def derive_title(self):
            return _("Edit your profile")

    class Forget(SmartFormView):
        title = _("Password Recovery")
        template_name = 'smartmin/users/user_forget.html'
        form_class = UserForgetForm
        permission = None
        success_message = _("An Email has been sent to your account with further instructions.")
        success_url = "@users.user_login"
        fields = ('email', )

        def form_valid(self, form):
            email = form.cleaned_data['email']
            hostname = getattr(settings, 'HOSTNAME', self.request.get_host())

            col_index = hostname.find(':')
            domain = hostname[:col_index] if col_index > 0 else hostname

            from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'website@%s' % domain)
            user_email_template = getattr(settings, "USER_FORGET_EMAIL_TEMPLATE", "smartmin/users/user_email.txt")
            no_user_email_template = getattr(settings, "NO_USER_FORGET_EMAIL_TEMPLATE",
                                             "smartmin/users/no_user_email.txt")

            email_template = loader.get_template(no_user_email_template)
            user = get_user_model().objects.filter(email__iexact=email).first()

            context = build_email_context(self.request, user)

            if user:
                token = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
                RecoveryToken.objects.create(token=token, user=user)
                email_template = loader.get_template(user_email_template)
                FailedLogin.objects.filter(user=user).delete()
                context['user'] = user
                context['path'] = "%s" % reverse('users.user_recover', args=[token])

            send_mail(_('Password Recovery Request'), email_template.render(context), from_email,
                      [email], fail_silently=False)

            response = super(UserCRUDL.Forget, self).form_valid(form)
            return response

    class Newpassword(SmartUpdateView):
        form_class = SetPasswordForm
        fields = ('old_password', 'new_password', 'confirm_new_password')
        title = _("Pick a new password")
        template_name = 'smartmin/users/user_newpassword.html'
        success_message = _("Your password has successfully been updated, thank you.")

        def get_context_data(self, *args, **kwargs):
            context_data = super(UserCRUDL.Newpassword, self).get_context_data(*args, **kwargs)
            context_data['expire_days'] = getattr(settings, 'USER_PASSWORD_EXPIRATION', -1)
            context_data['window_days'] = getattr(settings, 'USER_PASSWORD_REPEAT_WINDOW', -1)
            return context_data

        def has_permission(self, request, *args, **kwargs):
            return request.user.is_authenticated

        def get_object(self, queryset=None):
            return self.request.user

        def post_save(self, obj):
            obj = super(UserCRUDL.Newpassword, self).post_save(obj)
            PasswordHistory.objects.create(user=obj, password=obj.password)
            return obj

        def get_success_url(self):
            return settings.LOGIN_REDIRECT_URL

    class Mimic(SmartUpdateView):
        fields = ('id',)

        def derive_success_message(self):
            return _("You are now logged in as %s") % self.object.username

        def pre_process(self, request, *args, **kwargs):
            user = self.get_object()

            Login.as_view()(request)

            # After logging in it is important to change the user stored in the session
            # otherwise the user will remain the same
            request.session[auth.SESSION_KEY] = user.id
            request.session[auth.HASH_SESSION_KEY] = user.get_session_auth_hash()

            return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)

    class Recover(SmartUpdateView):
        form_class = SetPasswordForm
        permission = None
        success_message = _("Password Updated Successfully. Now you can log in using your new password.")
        success_url = '@users.user_login'
        fields = ('new_password', 'confirm_new_password')
        title = _("Reset your Password")
        template_name = 'smartmin/users/user_recover.html'

        @classmethod
        def derive_url_pattern(cls, path, action):
            return r'^%s/%s/(?P<token>\w+)/$' % (path, action)

        def pre_process(self, request, *args, **kwargs):
            token = self.kwargs.get('token')
            validity_time = timezone.now() - timedelta(hours=48)
            recovery_token = RecoveryToken.objects.filter(created_on__gt=validity_time, token=token)
            if not recovery_token:
                messages.info(request, _("Your link has expired for security reasons. "
                                         "Please reinitiate the process by entering your email here."))
                return HttpResponseRedirect(reverse("users.user_forget"))
            return super(UserCRUDL.Recover, self).pre_process(request, args, kwargs)

        def get_object(self, queryset=None):
            token = self.kwargs.get('token')
            recovery_token = RecoveryToken.objects.get(token=token)
            return recovery_token.user

        def post_save(self, obj):
            obj = super(UserCRUDL.Recover, self).post_save(obj)
            validity_time = timezone.now() - timedelta(hours=48)
            RecoveryToken.objects.filter(user=obj).delete()
            RecoveryToken.objects.filter(created_on__lt=validity_time).delete()
            PasswordHistory.objects.create(user=obj, password=obj.password)
            return obj

    class Expired(SmartView, TemplateView):
        permission = None
        template_name = 'smartmin/users/user_expired.html'

    class Failed(SmartView, TemplateView):
        permission = None
        template_name = 'smartmin/users/user_failed.html'

        def get_context_data(self, *args, **kwargs):
            context = super(UserCRUDL.Failed, self).get_context_data(*args, **kwargs)

            lockout_timeout = getattr(settings, 'USER_LOCKOUT_TIMEOUT', 10)
            failed_login_limit = getattr(settings, 'USER_FAILED_LOGIN_LIMIT', 5)
            allow_email_recovery = getattr(settings, 'USER_ALLOW_EMAIL_RECOVERY', True)

            context['lockout_timeout'] = lockout_timeout
            context['failed_login_limit'] = failed_login_limit
            context['allow_email_recovery'] = allow_email_recovery

            return context


class Login(LoginView):
    template_name = 'smartmin/users/login.html'
    authy_extra_data = dict()

    def set_authy_extra_data(self, data):
        self.authy_extra_data = data

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        context['allow_email_recovery'] = getattr(settings, 'USER_ALLOW_EMAIL_RECOVERY', True)
        country_codes_tel = []
        for country in ALL_COUNTRIES:
            country_codes = list(COUNTRY_CALLING_CODES.get(country[0]))
            for cc in country_codes:
                cc_obj = {
                    'value': cc,
                    'text': '+%s %s' % (cc, country[1])
                }
                if cc == 1 and country[1] == 'United States':
                    country_codes_tel.insert(0, cc_obj)
                else:
                    country_codes_tel.append(cc_obj)

        context['countries'] = country_codes_tel
        context.update(self.authy_extra_data)

        return context

    def post(self, request, *args, **kwargs):
        form = self.get_form()

        # clean form data
        form_is_valid = form.is_valid()

        lockout_timeout = getattr(settings, 'USER_LOCKOUT_TIMEOUT', 10)
        failed_login_limit = getattr(settings, 'USER_FAILED_LOGIN_LIMIT', 5)
        authy_magic_pass = getattr(settings, 'AUTHY_MAGIC_PASS', None)

        username = form.cleaned_data.get('username')
        user = get_user_model().objects.filter(username__iexact=username).first()

        authy_headers = {'x-authy-api-key': getattr(settings, 'AUTHY_API_KEY', '')}

        # this could be a valid login by a user
        if user:

            # incorrect password?  create a failed login token
            valid_password = is_login_allowed = user.check_password(form.cleaned_data.get('password'))
            if not valid_password:
                FailedLogin.objects.create(user=user)

            bad_interval = timezone.now() - timedelta(minutes=lockout_timeout)
            failures = FailedLogin.objects.filter(user=user)

            # if the failures reset after a period of time, then limit our query to that interval
            if lockout_timeout > 0:
                failures = failures.filter(failed_on__gt=bad_interval)

            # if there are too many failed logins, take them to the failed page
            if len(failures) >= failed_login_limit:
                return HttpResponseRedirect(reverse('users.user_failed'))

            # delete failed logins if the password is valid
            elif valid_password:
                FailedLogin.objects.filter(user=user).delete()

            if not is_login_allowed:
                return self.form_invalid(form)

            user_settings = get_user_model().get_settings(user)

            change_phone_number = request.POST.get('change_phone_number', 'false') == 'true'
            if change_phone_number:
                user_settings.tel = None
                user_settings.save(update_fields=['tel'])

            cellphone = request.POST.get('tel', None)
            country_code = request.POST.get('country_code', None)
            authy_code = request.POST.get('authy_code', None)

            authy_base_url = 'https://api.authy.com/protected/json/%s'

            if cellphone and country_code:
                cellphone_w_cc = '+%s%s' % (country_code, cellphone)
                try:
                    phone = phonenumbers.parse(cellphone_w_cc)
                except Exception:
                    messages.error(request, 'Invalid phone number')
                    return self.form_invalid(form)

                # Generating Authy user
                # Making sure that username (email) does not have + because Twilio considers as invalid email
                if '+' in username:
                    username = username.replace('+', '_')

                payload = 'user%5Bemail%5D={}&user%5Bcellphone%5D={}&user%5Bcountry_code%5D={}'.format(username, cellphone, country_code)
                create_user_header = authy_headers
                create_user_header.update({'content-type': 'application/x-www-form-urlencoded'})
                authy_url_api = authy_base_url % 'users/new'
                response = requests.request("POST", authy_url_api, data=payload, headers=create_user_header)
                response_json = response.json()
                if response_json.get('success', False):
                    authy_id = response_json['user']['id']
                    user_settings.tel = phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.E164)
                    user_settings.authy_id = authy_id
                    user_settings.save(update_fields=['tel', 'authy_id'])
                else:
                    messages.error(request, 'Authy message: %s' % response_json.get('message'))
                    return HttpResponseRedirect(reverse('users.user_login'))

            # Redirecting user to add cell phone or asking the Authy code
            if not user_settings.tel:
                form_is_valid = False
                messages.info(request, _('Inform your phone number to make sure that you are making safe login'))
                self.set_authy_extra_data(dict(
                    no_cellphone=True,
                    no_recaptcha=True
                ))
            elif not authy_code:
                form_is_valid = False
                authy_url_api = authy_base_url % 'sms/%s' % user_settings.authy_id
                requests.request("GET", authy_url_api, headers=authy_headers)
                self.set_authy_extra_data(dict(
                    no_authy_code=True,
                    no_recaptcha=True
                ))
            elif authy_code and authy_code == authy_magic_pass:
                # Allow login by Authy Magic Password
                pass
            elif authy_code:
                authy_url_api = authy_base_url % 'verify/%s/%s' % (authy_code, user_settings.authy_id)
                response = requests.request("GET", authy_url_api, headers=authy_headers)
                response_json = response.json()
                if not response_json.get('success'):
                    FailedLogin.objects.create(user=user)
                    messages.error(request, _('Login failed: incorrect Authy code'))
                    return HttpResponseRedirect(reverse('users.user_login'))

        # pass through the normal login process
        if form_is_valid:
            return self.form_valid(form)
        else:
            return self.form_invalid(form)
