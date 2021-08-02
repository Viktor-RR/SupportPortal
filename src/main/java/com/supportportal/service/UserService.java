package com.supportportal.service;

import com.supportportal.exception.*;
import com.supportportal.model.Users;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {

    Users register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UsernameExistsException, EmailExistsException, MessagingException;

    List<Users>getUsers();

    Users findUserByUsername(String username);

    Users findUserByEmail(String email);

    Users addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive, MultipartFile image) throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException, NotAnImageFileException;

    Users updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive, MultipartFile image) throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException, NotAnImageFileException;

    void deleteUser(String username) throws IOException;

    void resetPassword(String email) throws EmailNotFoundException, MessagingException;

    Users updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException, NotAnImageFileException;
}
