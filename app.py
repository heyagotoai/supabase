import streamlit as st
import re
from supabase import create_client, Client

# Inicjalizacja połączenia z Supabase
@st.cache_resource
def init_connection():
    url = st.secrets["connections"]["supabase"]["SUPABASE_URL"]
    key = st.secrets["connections"]["supabase"]["SUPABASE_KEY"]
    return create_client(url, key)

supabase = init_connection()

def validate_email(email):
    """Walidacja formatu email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Walidacja hasła - minimum 8 znaków, jedna wielka litera, jedna cyfra"""
    if len(password) < 8:
        return False, "Hasło musi mieć co najmniej 8 znaków"
    if not re.search(r'[A-Z]', password):
        return False, "Hasło musi zawierać co najmniej jedną wielką literę"
    if not re.search(r'\d', password):
        return False, "Hasło musi zawierać co najmniej jedną cyfrę"
    return True, "Hasło poprawne"

def check_email_exists(email):
    """Sprawdzenie czy email już istnieje w bazie"""
    try:
        # Próba rejestracji z istniejącym emailem
        response = supabase.auth.sign_up({
            "email": email,
            "password": "temp_password_for_check"
        })
        
        # Jeśli user istnieje ale nie ma identities, to email już jest zarejestrowany
        if (response.user and 
            hasattr(response.user, 'identities') and 
            response.user.identities is not None and
            len(response.user.identities) == 0):
            return True
        return False
    except Exception:
        return False

def sign_up(email, password, first_name, last_name):
    """Funkcja rejestracji użytkownika"""
    try:
        response = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": {
                    "first_name": first_name,
                    "last_name": last_name
                }
            }
        })
        return response, None
    except Exception as e:
        return None, str(e)

def sign_in(email, password):
    """Funkcja logowania użytkownika"""
    try:
        response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        return response, None
    except Exception as e:
        return None, str(e)

def sign_out():
    """Funkcja wylogowania"""
    supabase.auth.sign_out()
    st.session_state.clear()

def check_auth():
    """Sprawdzenie czy użytkownik jest zalogowany"""
    return 'user' in st.session_state and st.session_state.user is not None

def registration_form():
    """Formularz rejestracji z walidacjami"""
    st.subheader("Rejestracja")
    
    with st.form("registration_form"):
        first_name = st.text_input("Imię", max_chars=50)
        last_name = st.text_input("Nazwisko", max_chars=50)
        email = st.text_input("Email")
        # Normalizacja emaila: usunięcie białych znaków i zamiana na małe litery
        email = email.strip().lower()
        password = st.text_input("Hasło", type="password")
        confirm_password = st.text_input("Potwierdź hasło", type="password")
        
        submitted = st.form_submit_button("Zarejestruj się")
        
        if submitted:
            # Walidacja pól
            if not all([first_name, last_name, email, password, confirm_password]):
                st.error("Wszystkie pola są wymagane")
                return
            
            # Walidacja email
            if not validate_email(email):
                st.error("Nieprawidłowy format email")
                return
            
            # Walidacja hasła
            is_valid, message = validate_password(password)
            if not is_valid:
                st.error(message)
                return
            
            # Sprawdzenie czy hasła się zgadzają
            if password != confirm_password:
                st.error("Hasła nie są identyczne")
                return
            
            # Rejestracja użytkownika
            response, error = sign_up(email, password, first_name, last_name)
            
            if error:
                # Przyjazne komunikaty w zależności od treści błędu
                lower_err = error.lower()
                if "already exists" in lower_err or "already registered" in lower_err or "email_exists" in lower_err:
                    st.error("Użytkownik z tym adresem e-mail już istnieje. Zaloguj się lub zresetuj hasło.")
                elif "for security purposes" in lower_err or "after 59 seconds" in lower_err:
                    st.error("Odśwież stronę lub odczekaj minutę przed ponowną próbą rejestracji tym adresem e-mail.")
                else:
                    st.error(f"Błąd rejestracji: {error}")
            else:
                # Supabase zwraca user.identities == [] gdy e-mail jest już zarejestrowany
                if (response and response.user and
                    hasattr(response.user, 'identities') and
                    response.user.identities is not None and
                    len(response.user.identities) == 0):
                    st.error("Użytkownik z tym adresem e-mail już istnieje. Zaloguj się lub zresetuj hasło.")
                else:
                    st.success("Konto zostało utworzone! Sprawdź email w celu aktywacji konta.")

def login_form():
    """Formularz logowania"""
    st.subheader("Logowanie")
    
    with st.form("login_form"):
        email = st.text_input("Email")
        # Normalizacja emaila: usunięcie białych znaków i zamiana na małe litery
        email = email.strip().lower()
        password = st.text_input("Hasło", type="password")
        
        submitted = st.form_submit_button("Zaloguj się")
        
        if submitted:
            if not email or not password:
                st.error("Email i hasło są wymagane")
                return
            
            if not validate_email(email):
                st.error("Nieprawidłowy format email")
                return
            
            response, error = sign_in(email, password)
            
            if error:
                # Przyjazna informacja w przypadku nieaktywowanego konta
                if "Invalid login credentials" in error:
                    st.error("Nieprawidłowe dane logowania lub konto nie zostało jeszcze aktywowane. Sprawdź skrzynkę pocztową i kliknij link aktywacyjny.")
                else:
                    # Spróbuj wypisać dodatkowe informacje diagnostyczne, jeżeli obiekt błędu je posiada
                    err_msg = f"Błąd logowania: {error}"
                    # Jeśli błąd jest obiektem wyjątku, spróbuj pobrać dodatkowe atrybuty
                    if not isinstance(error, str):
                        code = getattr(error, 'code', None)
                        status = getattr(error, 'status', None)
                        if code:
                            err_msg += f" (code: {code})"
                        if status:
                            err_msg += f" (status: {status})"
                    st.error(err_msg)
            elif response and response.user:
                st.session_state.user = response.user
                st.success("Logowanie zakończone sukcesem!")
                st.rerun()
            else:
                st.error("Błąd logowania: Nieprawidłowa odpowiedź serwera")

def update_user_profile(first_name: str, last_name: str):
    """Aktualizuje imię i nazwisko użytkownika w Supabase"""
    user_id = st.session_state.user.id
    # Aktualizacja metadanych użytkownika (auth)
    supabase.auth.update_user({
        "data": {
            "first_name": first_name,
            "last_name": last_name
        }
    })
    # Aktualizacja rekordu w tabeli profiles (jeżeli istnieje)
    supabase.table("profiles").update({
        "first_name": first_name,
        "last_name": last_name
    }).eq("id", user_id).execute()


def update_user_password(new_password: str):
    """Zmienia hasło zalogowanego użytkownika"""
    supabase.auth.update_user({
        "password": new_password
    })


def edit_profile_form():
    """Formularz pozwalający użytkownikowi edytować dane profilu"""
    st.subheader("Edycja danych profilu")

    # Domyślne wartości pobieramy z profilu
    user_data = supabase.table("profiles").select("first_name", "last_name").eq("id", st.session_state.user.id).execute()
    default_first = user_data.data[0].get("first_name", "") if user_data.data else ""
    default_last = user_data.data[0].get("last_name", "") if user_data.data else ""

    with st.form("edit_profile_form"):
        first_name = st.text_input("Imię", value=default_first, max_chars=50)
        last_name = st.text_input("Nazwisko", value=default_last, max_chars=50)

        st.markdown("---")
        st.write("Zmiana hasła (opcjonalnie)")
        new_password = st.text_input("Nowe hasło", type="password")
        confirm_password = st.text_input("Potwierdź nowe hasło", type="password")

        submitted = st.form_submit_button("Zapisz zmiany")

        if submitted:
            # Walidacja imienia i nazwiska
            if not first_name or not last_name:
                st.error("Imię i nazwisko nie mogą być puste")
                return

            try:
                update_user_profile(first_name, last_name)
            except Exception as e:
                st.error(f"Nie udało się zaktualizować danych profilu: {e}")
                return

            # Obsługa zmiany hasła, jeśli podano
            if new_password or confirm_password:
                if new_password != confirm_password:
                    st.error("Hasła nie są identyczne")
                    return
                valid, message = validate_password(new_password)
                if not valid:
                    st.error(message)
                    return
                try:
                    update_user_password(new_password)
                except Exception as e:
                    st.error(f"Nie udało się zaktualizować hasła: {e}")
                    return

            st.success("Dane profilu zostały zaktualizowane")
            # Po udanej aktualizacji wracamy do widoku panelu
            st.session_state.edit_profile = False
            st.rerun()

    # Przycisk anulujący edycję
    if st.button("Anuluj"):
        st.session_state.edit_profile = False
        st.rerun()

def main_app():
    """Główna aplikacja dla zalogowanych użytkowników"""
    st.title("Panel użytkownika")

    # Inicjalizacja flagi edycji, jeśli nie istnieje
    if "edit_profile" not in st.session_state:
        st.session_state.edit_profile = False

    if st.session_state.user:
        # Jeżeli użytkownik zdecydował się edytować profil – pokaż formularz
        if st.session_state.edit_profile:
            edit_profile_form()
            return  # Nie pokazujemy dalszej części panelu w trybie edycji

        # Widok podstawowy
        st.write(f"Witaj, {st.session_state.user.email}!")

        # Wyświetlenie informacji o użytkowniku
        user_data = supabase.table("profiles").select("* ").eq("id", st.session_state.user.id).execute()
        if user_data.data:
            profile = user_data.data[0]
            st.write(f"Imię: {profile.get('first_name', 'Brak')}")
            st.write(f"Nazwisko: {profile.get('last_name', 'Brak')}")

        # Wyświetlenie ról użytkownika
        roles_data = supabase.table("user_roles").select("role").eq("user_id", st.session_state.user.id).execute()
        if roles_data.data:
            roles = [role['role'] for role in roles_data.data]
            st.write(f"Role: {', '.join(roles)}")

        st.markdown("---")
        # Przyciski akcji
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Edytuj dane"):
                st.session_state.edit_profile = True
                st.rerun()
        with col2:
            if st.button("Wyloguj się"):
                sign_out()
                st.rerun()

def main():
    """Główna funkcja aplikacji"""
    st.title("Career Guide")
    
    if not check_auth():
        tab1, tab2 = st.tabs(["Logowanie", "Rejestracja"])
        
        with tab1:
            login_form()
        
        with tab2:
            registration_form()
    else:
        main_app()

if __name__ == "__main__":
    main()
