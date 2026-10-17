-- 1. Security Package Specification
CREATE OR REPLACE PACKAGE "QA_SECURITY_PKG" AS 
    FUNCTION GET_CURRENT_USER RETURN VARCHAR2; 
    FUNCTION HASH_PASSWORD (p_username IN VARCHAR2, p_password IN VARCHAR2, p_salt IN VARCHAR2) RETURN VARCHAR2; 
    PROCEDURE REGISTER_USER (p_username IN VARCHAR2, p_password IN VARCHAR2, p_full_name IN VARCHAR2, p_email IN VARCHAR2 DEFAULT NULL, p_mobile_no IN VARCHAR2 DEFAULT NULL, p_app_role IN VARCHAR2 DEFAULT NULL); 
    FUNCTION AUTHENTICATE_USER (p_username IN VARCHAR2, p_password IN VARCHAR2) RETURN BOOLEAN; 
    PROCEDURE POST_LOGIN_INIT; 
    PROCEDURE CHANGE_PASSWORD (p_username IN VARCHAR2, p_new_password IN VARCHAR2); 
    PROCEDURE SEND_PASSWORD_RESET_OTP (p_user_or_email IN VARCHAR2); 
    PROCEDURE VERIFY_OTP_AND_RESET (p_user_or_email IN VARCHAR2, p_otp IN VARCHAR2, p_new_password IN VARCHAR2); 
    FUNCTION IS_ADMIN RETURN VARCHAR2; 
    FUNCTION FNC_GET_APEX_LOCAL_USER_NAME (PRM_USER_ID IN VARCHAR2) RETURN VARCHAR2 DETERMINISTIC;
END "QA_SECURITY_PKG";
/

-- 2. Security Package Body (Dependent on QA_USER_PROFILE)
CREATE OR REPLACE PACKAGE BODY "QA_SECURITY_PKG" AS 
    c_sender_email CONSTANT VARCHAR2(100) := 'shindepradip325@gmail.com'; 

    FUNCTION GET_CURRENT_USER RETURN VARCHAR2 IS 
    BEGIN 
        RETURN UPPER(COALESCE(SYS_CONTEXT('APEX$SESSION', 'APP_USER'), USER)); 
    END GET_CURRENT_USER; 

    FUNCTION HASH_PASSWORD (p_username IN VARCHAR2, p_password IN VARCHAR2, p_salt IN VARCHAR2) RETURN VARCHAR2 IS 
        l_hash VARCHAR2(128); 
    BEGIN 
        SELECT STANDARD_HASH(UPPER(TRIM(p_username)) || ':' || p_salt || ':' || p_password, 'SHA256') 
          INTO l_hash 
          FROM DUAL; 
        RETURN l_hash; 
    END HASH_PASSWORD; 

    PROCEDURE REGISTER_USER (p_username IN VARCHAR2, p_password IN VARCHAR2, p_full_name IN VARCHAR2, p_email IN VARCHAR2 DEFAULT NULL, p_mobile_no IN VARCHAR2 DEFAULT NULL, p_app_role IN VARCHAR2 DEFAULT NULL) IS 
        l_clean_user VARCHAR2(100) := UPPER(TRIM(p_username)); 
        l_clean_mail VARCHAR2(255) := LOWER(TRIM(p_email)); 
        l_salt       VARCHAR2(64)  := DBMS_RANDOM.STRING('X', 32); 
        l_hash       VARCHAR2(128); 
        l_user_count NUMBER; 
        l_role       VARCHAR2(30); 
    BEGIN 
        SELECT COUNT(*) INTO l_user_count FROM QA_USER_PROFILE; 
        IF p_app_role IS NOT NULL THEN 
            l_role := UPPER(p_app_role); 
        ELSE 
            l_role := CASE WHEN l_user_count = 0 THEN 'ADMIN' ELSE 'USER' END; 
        END IF; 

        l_hash := HASH_PASSWORD(l_clean_user, p_password, l_salt); 

        INSERT INTO QA_USER_PROFILE (
            USERNAME, PASSWORD_HASH, PASSWORD_SALT, FULL_NAME, EMAIL, MOBILE_NO, APP_ROLE, IS_ACTIVE_YN, CREATED_BY, UPDATED_BY
        ) VALUES (
            l_clean_user, l_hash, l_salt, p_full_name, l_clean_mail, p_mobile_no, l_role, 'Y', l_clean_user, l_clean_user
        ); 

        IF l_clean_mail IS NOT NULL THEN 
            APEX_MAIL.SEND(
                p_to   => l_clean_mail, 
                p_from => c_sender_email, 
                p_subj => 'Welcome to QA Inspection Report - Login Credentials', 
                p_body => 'Dear ' || p_full_name || ',' || CHR(10) || CHR(10) || 
                          'Your account has been created in QA Inspection Report.' || CHR(10) || 
                          'Username: ' || l_clean_user || CHR(10) || 
                          'Password: ' || p_password || CHR(10) || 
                          'Created Date: ' || TO_CHAR(SYSDATE, 'DD-Mon-YYYY') || CHR(10) || 
                          'Status: Active' || CHR(10) || CHR(10) || 
                          'Regards,' || CHR(10) || 
                          'Pradip Shinde' || CHR(10) || 
                          '7218312593' 
            ); 
            APEX_MAIL.PUSH_QUEUE; 
        END IF; 
    END REGISTER_USER; 

    FUNCTION AUTHENTICATE_USER (p_username IN VARCHAR2, p_password IN VARCHAR2) RETURN BOOLEAN IS 
        l_clean_user   VARCHAR2(100) := UPPER(TRIM(p_username)); 
        l_stored_hash  QA_USER_PROFILE.PASSWORD_HASH%TYPE; 
        l_stored_salt  QA_USER_PROFILE.PASSWORD_SALT%TYPE; 
        l_is_active    QA_USER_PROFILE.IS_ACTIVE_YN%TYPE; 
        l_compute_hash VARCHAR2(128); 
    BEGIN 
        SELECT PASSWORD_HASH, PASSWORD_SALT, IS_ACTIVE_YN 
          INTO l_stored_hash, l_stored_salt, l_is_active 
          FROM QA_USER_PROFILE 
         WHERE USERNAME = l_clean_user; 

        IF l_is_active != 'Y' THEN 
            APEX_UTIL.SET_CUSTOM_AUTH_STATUS(p_status => 'Account is deactivated. Contact Administrator.'); 
            APEX_UTIL.SET_AUTHENTICATION_RESULT(2); 
            RETURN FALSE; 
        END IF; 

        l_compute_hash := HASH_PASSWORD(l_clean_user, p_password, l_stored_salt); 

        IF l_compute_hash = l_stored_hash THEN 
            APEX_UTIL.SET_AUTHENTICATION_RESULT(0); 
            RETURN TRUE; 
        ELSE 
            UPDATE QA_USER_PROFILE 
               SET FAILED_LOGINS = FAILED_LOGINS + 1 
             WHERE USERNAME = l_clean_user; 
            COMMIT; 
            APEX_UTIL.SET_CUSTOM_AUTH_STATUS(p_status => 'Invalid username or password.'); 
            APEX_UTIL.SET_AUTHENTICATION_RESULT(4); 
            RETURN FALSE; 
        END IF; 
    EXCEPTION 
        WHEN NO_DATA_FOUND THEN 
            APEX_UTIL.SET_CUSTOM_AUTH_STATUS(p_status => 'Invalid username or password.'); 
            APEX_UTIL.SET_AUTHENTICATION_RESULT(1); 
            RETURN FALSE; 
    END AUTHENTICATE_USER; 

    PROCEDURE POST_LOGIN_INIT IS 
    BEGIN 
        UPDATE QA_USER_PROFILE 
           SET LAST_LOGIN = CURRENT_TIMESTAMP, FAILED_LOGINS = 0 
         WHERE USERNAME = GET_CURRENT_USER; 
    END POST_LOGIN_INIT; 

    PROCEDURE CHANGE_PASSWORD (p_username IN VARCHAR2, p_new_password IN VARCHAR2) IS 
        l_clean_user VARCHAR2(100) := UPPER(TRIM(p_username)); 
        l_new_salt   VARCHAR2(64)  := DBMS_RANDOM.STRING('X', 32); 
        l_new_hash   VARCHAR2(128); 
    BEGIN 
        l_new_hash := HASH_PASSWORD(l_clean_user, p_new_password, l_new_salt); 
        UPDATE QA_USER_PROFILE 
           SET PASSWORD_HASH = l_new_hash, 
               PASSWORD_SALT = l_new_salt, 
               RESET_OTP     = NULL, 
               OTP_EXPIRY    = NULL, 
               OTP_ATTEMPTS  = 0, 
               FAILED_LOGINS = 0, 
               UPDATED       = CURRENT_TIMESTAMP, 
               UPDATED_BY    = GET_CURRENT_USER 
         WHERE USERNAME = l_clean_user; 
    END CHANGE_PASSWORD; 

    PROCEDURE SEND_PASSWORD_RESET_OTP (p_user_or_email IN VARCHAR2) IS 
        l_input     VARCHAR2(255) := TRIM(p_user_or_email); 
        l_username  QA_USER_PROFILE.USERNAME%TYPE; 
        l_full_name QA_USER_PROFILE.FULL_NAME%TYPE; 
        l_email     QA_USER_PROFILE.EMAIL%TYPE; 
        l_otp       VARCHAR2(6); 
    BEGIN 
        SELECT USERNAME, FULL_NAME, EMAIL 
          INTO l_username, l_full_name, l_email 
          FROM QA_USER_PROFILE 
         WHERE USERNAME = UPPER(l_input) 
            OR LOWER(EMAIL) = LOWER(l_input); 

        IF l_email IS NULL THEN 
            RAISE_APPLICATION_ERROR(-20010, 'No email address is registered for this user.'); 
        END IF; 

        l_otp := TO_CHAR(TRUNC(DBMS_RANDOM.VALUE(100000, 999999))); 

        UPDATE QA_USER_PROFILE 
           SET RESET_OTP    = l_otp, 
               OTP_EXPIRY   = CURRENT_TIMESTAMP + INTERVAL '10' MINUTE, 
               OTP_ATTEMPTS = 0 
         WHERE USERNAME = l_username; 

        APEX_MAIL.SEND(
            p_to   => l_email, 
            p_from => c_sender_email, 
            p_subj => 'Password Reset OTP for ' || l_username || ' - ' || TO_CHAR(SYSDATE, 'DD-MON-YYYY'), 
            p_body => 'Dear ' || l_full_name || ',' || CHR(10) || 
                      'A password reset was requested for your account (' || l_username || ').' || CHR(10) || 
                      'Your 6-Digit OTP: ' || l_otp || CHR(10) || 
                      'Valid For: 10 Minutes' || CHR(10) || 
                      'Request Date: ' || TO_CHAR(SYSDATE, 'DD-Mon-YYYY HH:MI AM') || CHR(10) || 
                      'Status: Pending OTP Verification' || CHR(10) || CHR(10) || 
                      'Regards,' || CHR(10) || 
                      'Pradip Shinde' || CHR(10) || 
                      '7218312593' 
        ); 
        COMMIT; 
        APEX_MAIL.PUSH_QUEUE; 
    EXCEPTION 
        WHEN NO_DATA_FOUND THEN 
            RAISE_APPLICATION_ERROR(-20011, 'No user found with that Username or Email.'); 
    END SEND_PASSWORD_RESET_OTP; 

    PROCEDURE VERIFY_OTP_AND_RESET (p_user_or_email IN VARCHAR2, p_otp IN VARCHAR2, p_new_password IN VARCHAR2) IS 
        l_input      VARCHAR2(255) := TRIM(p_user_or_email); 
        l_username   QA_USER_PROFILE.USERNAME%TYPE; 
        l_full_name  QA_USER_PROFILE.FULL_NAME%TYPE; 
        l_email      QA_USER_PROFILE.EMAIL%TYPE; 
        l_stored_otp QA_USER_PROFILE.RESET_OTP%TYPE; 
        l_expiry     QA_USER_PROFILE.OTP_EXPIRY%TYPE; 
        l_attempts   QA_USER_PROFILE.OTP_ATTEMPTS%TYPE; 
    BEGIN 
        SELECT USERNAME, FULL_NAME, EMAIL, RESET_OTP, OTP_EXPIRY, NVL(OTP_ATTEMPTS, 0) 
          INTO l_username, l_full_name, l_email, l_stored_otp, l_expiry, l_attempts 
          FROM QA_USER_PROFILE 
         WHERE USERNAME = UPPER(l_input) 
            OR LOWER(EMAIL) = LOWER(l_input); 

        IF l_attempts >= 5 THEN 
            RAISE_APPLICATION_ERROR(-20012, 'Maximum OTP attempts exceeded. Please request a new OTP.'); 
        END IF; 

        IF l_stored_otp IS NULL OR l_expiry IS NULL OR CURRENT_TIMESTAMP > l_expiry THEN 
            RAISE_APPLICATION_ERROR(-20013, 'OTP has expired or was not requested. Please request a new OTP.'); 
        END IF; 

        IF TRIM(p_otp) != l_stored_otp THEN 
            UPDATE QA_USER_PROFILE 
               SET OTP_ATTEMPTS = NVL(OTP_ATTEMPTS, 0) + 1 
             WHERE USERNAME = l_username; 
            COMMIT; 
            RAISE_APPLICATION_ERROR(-20014, 'Invalid OTP entered. Please check your email and try again.'); 
        END IF; 

        CHANGE_PASSWORD(p_username => l_username, p_new_password => p_new_password); 

        IF l_email IS NOT NULL THEN 
            APEX_MAIL.SEND(
                p_to   => l_email, 
                p_from => c_sender_email, 
                p_subj => 'Password Reset Successful - ' || l_username, 
                p_body => 'Dear ' || l_full_name || ',' || CHR(10) || 
                          'Your password for QA Inspection Report has been successfully reset.' || CHR(10) || 
                          'Username: ' || l_username || CHR(10) || 
                          'Verification Mode: By Email OTP' || CHR(10) || 
                          'Reset Date: ' || TO_CHAR(SYSDATE, 'DD-Mon-YYYY HH:MI AM') || CHR(10) || 
                          'Status: Completed' || CHR(10) || CHR(10) || 
                          'Regards,' || CHR(10) || 
                          'Pradip Shinde' || CHR(10) || 
                          '7218312593' 
            ); 
        END IF; 
        COMMIT; 
        APEX_MAIL.PUSH_QUEUE; 
    EXCEPTION 
        WHEN NO_DATA_FOUND THEN 
            RAISE_APPLICATION_ERROR(-20011, 'No user found with that Username or Email.'); 
    END VERIFY_OTP_AND_RESET; 

    FUNCTION IS_ADMIN RETURN VARCHAR2 IS 
        l_role VARCHAR2(30); 
    BEGIN 
        SELECT APP_ROLE 
          INTO l_role 
          FROM QA_USER_PROFILE 
         WHERE USERNAME = GET_CURRENT_USER 
           AND IS_ACTIVE_YN = 'Y'; 
        RETURN CASE WHEN l_role = 'ADMIN' THEN 'Y' ELSE 'N' END; 
    EXCEPTION 
        WHEN NO_DATA_FOUND THEN 
            RETURN 'N'; 
    END IS_ADMIN; 

    FUNCTION FNC_GET_APEX_LOCAL_USER_NAME (PRM_USER_ID IN VARCHAR2) RETURN VARCHAR2 DETERMINISTIC AS 
        V_USER VARCHAR2(100); 
    BEGIN 
        SELECT INITCAP(FULL_NAME) 
          INTO V_USER 
          FROM QA_USER_PROFILE 
         WHERE UPPER(USERNAME) = UPPER(PRM_USER_ID); 
        RETURN V_USER; 
    EXCEPTION 
        WHEN OTHERS THEN 
            RETURN PRM_USER_ID; 
    END FNC_GET_APEX_LOCAL_USER_NAME; 
END "QA_SECURITY_PKG";
/
