# https://github.com/django/django/blob/master/django/contrib/auth/views.py#L247


from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.shortcuts import render, redirect

# must take token in form 'uidb64' as argument?


def change_password_confirm(request, token):
    if check_token(token):
        # for instant use https://github.com/django/django/blob/d6aff369ad33457ae2355b5b210faf1c4890ff35/django/contrib/auth/tokens.py#L24
        if request.method == 'POST':
            form = PasswordChangeForm(request.user, request.POST)
            if form.is_valid():
                user = form.save()
                # keep user logged in after change password
                update_session_auth_hash(request, user)
                messages.success(
                    request, 'Your password was successfully updated!')
                return redirect('')
            else:
                messages.error(request, 'Please correct the error below.')
        else:
            form = PasswordChangeForm(request.user)
        return render(request, 'password_reset/change_password.html', {
            'form': form
        })
    else:
        messages.error(request, 'Your link is expired. Please, try again.')
