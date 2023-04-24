package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username       string
	HashedPassword []byte
	SymmetricKey   []byte
	HMACKey        []byte
	PrivateKey     userlib.PKEDecKey
	SigningKey     userlib.DSSignKey
	FilesOwned     map[uuid.UUID]uuid.UUID // [hashedFilenameUUID]: fileOwnerInfoUUID
	FilesShared    map[uuid.UUID]uuid.UUID // [hashedFilenameUUID]: InvitationUUID

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	Content []byte
}

type FilePointer struct {
	OriginalFileObjectUUID uuid.UUID
	LatestFileObjectUUID   uuid.UUID
}

type FileObject struct {
	FileUUID           uuid.UUID
	NextFileObjectUUID uuid.UUID
}

// FileSymmetricKey and FileHMACKey is used to encrypt both FilePointer and File
type FileKeys struct {
	FileSymmetricKey []byte
	FileHMACKey      []byte
	OwnerUsername    string
	UsersSharedWith  map[string][]string // [senderUsername]: recipientUsername
	FilePointerUUID  uuid.UUID
}

// Public-Key Encrypted
type InvitationKeys struct {
	SK []byte
	HK []byte
	ID uuid.UUID
}

type Invitation struct {
	FileKeysSymmetricKey []byte
	FileKeysHMACKey      []byte
	FileKeysUUID         uuid.UUID
	InvitationSalt       string
	SenderUsername       string
}

type FileOwnerInfo struct {
	FileKeysSymmetricKey []byte
	FileKeysHMACKey      []byte
	FileKeysUUID         uuid.UUID
	InvitationSalt       string
}

// Set global values
var lengthOfKey int = 16
var lengthOfSHAKey int = 256
var lengthOfMAC int = 64
var lengthOfHash int = 16
var lengthOfPadding int = 16
var filenamePadding string = strings.Repeat("A", lengthOfPadding)

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {

	// Throw errer if username is empty
	if username == "" {
		return nil, errors.New(strings.ToTitle("The username must have a length of minimum 1 character"))
	}

	// Throw error if user exists
	if checkIfUserExists(username) {
		return nil, errors.New(strings.ToTitle("The username already exists"))
	}

	var userdata User
	var publicKey userlib.PKEEncKey
	var privateKey userlib.PKEDecKey

	// Salts
	hashedPasswordSalt := "hashedPasswordSalt"
	symmetricKeySalt := username

	// Hash password
	hashedPassword := userlib.Hash([]byte(password + hashedPasswordSalt))

	// Generating keys
	publicKey, privateKey, err = userlib.PKEKeyGen()
	signingKey, verificationKey, err := userlib.DSKeyGen()

	// Keystore
	usernamePublicKeyID := username + "PublicKey"
	usernameVerificationKeyID := username + "VerificationKey"

	err = userlib.KeystoreSet(usernamePublicKeyID, publicKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(usernameVerificationKeyID, verificationKey)
	if err != nil {
		return nil, err
	}

	// Derive symmetricKey
	symmetricKey := userlib.Argon2Key([]byte(hashedPassword), []byte(symmetricKeySalt), 16)

	// Derive HMACKey
	HMACKey, err := userlib.HashKDF(symmetricKey, []byte("HMAC of userdata"))
	if err != nil {
		return nil, err
	}

	// Set values of userdata
	userdata.Username = username
	userdata.HashedPassword = hashedPassword
	userdata.SymmetricKey = symmetricKey
	userdata.HMACKey = HMACKey[:lengthOfKey]
	userdata.FilesOwned = make(map[uuid.UUID]uuid.UUID)
	userdata.FilesShared = make(map[uuid.UUID]uuid.UUID)
	userdata.PrivateKey = privateKey
	userdata.SigningKey = signingKey

	// Derive UUID of userdata
	hashedUsername := userlib.Hash([]byte(username))
	usernameUUID, err := uuid.FromBytes(hashedUsername[:16])
	if err != nil {
		return nil, err
	}

	// Marshal userdata
	userdataMarshal, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	// Encrypt userdata
	encryptedUserdataMarshal := userlib.SymEnc(symmetricKey, userlib.RandomBytes(lengthOfKey), userdataMarshal)

	// Derive HMAC, add it and store userdata in Datastore
	HMAC, err := userlib.HMACEval(HMACKey[:lengthOfKey], encryptedUserdataMarshal)
	if err != nil {
		return nil, err
	}
	HMACEncryptedUserdataMarshal := append(encryptedUserdataMarshal, HMAC...)
	userlib.DatastoreSet(usernameUUID, HMACEncryptedUserdataMarshal)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Throw error if user doesn't exist
	if !checkIfUserExists(username) {
		return nil, err
	}

	// Retrieve SymmetricKey and HMACKey

	// Salts
	hashedPasswordSalt := "hashedPasswordSalt"
	symmetricKeySalt := username

	// Hash password
	hashedPassword := userlib.Hash([]byte(password + hashedPasswordSalt))

	// Derive symmetricKey
	symmetricKey := userlib.Argon2Key([]byte(hashedPassword), []byte(symmetricKeySalt), 16)

	// Derive HMACKey
	HMACKey, err := userlib.HashKDF(symmetricKey, []byte("HMAC of userdata"))
	if err != nil {
		return nil, err
	}

	// Get UUID of userdata
	hashedUsername := userlib.Hash([]byte(username))
	usernameUUID, err := uuid.FromBytes(hashedUsername[:16])
	if err != nil {
		return nil, err
	}

	// Get userdata from Datastore
	storedUserdataMarshal, err := ReadFromDatastore(usernameUUID, symmetricKey, HMACKey[:lengthOfKey])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(storedUserdataMarshal, userdataptr)
	if err != nil {
		return nil, err
	}

	// Set keys
	userdata.Username = username
	userdata.HashedPassword = hashedPassword
	userdata.SymmetricKey = symmetricKey
	userdata.HMACKey = HMACKey[:lengthOfKey]

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var filedata File
	var fileUUID uuid.UUID

	// Update userdata in case of multiple sessions
	userdata, err = UpdateUser(userdata.Username, userdata.HashedPassword)
	if err != nil {
		return err
	}

	// Get fileUUID if file exists, create a new fileUUID if file does not exist in userdata.FilesOwned or userdata.FilesShared
	if !checkIfFilenameExists(filename, *userdata) {
		fileUUID = uuid.New()
	} else {
		fileUUID, err = getOriginalFileUUID(filename, *userdata)
		if err != nil {
			return err
		}
	}

	// Check if file exists in Datastore
	_, ok := userlib.DatastoreGet(fileUUID)

	// If ok is false, then the file does not exist - run first block
	if !ok {

		var fileOwnerInfo FileOwnerInfo
		var fileKeys FileKeys
		var filePointer FilePointer
		var fileObject FileObject
		usersSharedWith := make(map[string][]string)

		// Define UUIDs
		fileOwnerInfoUUID := uuid.New()
		fileKeysUUID := uuid.New()
		filePointerUUID := uuid.New()
		originalFileObjectUUID := uuid.New()
		nextFileObjectUUID := uuid.New()
		fileUUID := uuid.New()

		// Define invitationSalt of file
		invitationSalt := string(userlib.Hash([]byte(filename)))

		// Fix fileOwnerInfo
		fileOwnerInfo.FileKeysSymmetricKey = userlib.RandomBytes(lengthOfKey)
		fileOwnerInfo.FileKeysHMACKey = userlib.RandomBytes(lengthOfKey)
		fileOwnerInfo.FileKeysUUID = fileKeysUUID
		fileOwnerInfo.InvitationSalt = invitationSalt

		// Fix fileKeys
		fileKeys.FileSymmetricKey = userlib.RandomBytes(lengthOfKey)
		fileKeys.FileHMACKey = userlib.RandomBytes(lengthOfKey)
		fileKeys.FilePointerUUID = filePointerUUID
		fileKeys.OwnerUsername = userdata.Username
		fileKeys.UsersSharedWith = usersSharedWith

		// Fix FilePointer
		filePointer.OriginalFileObjectUUID = originalFileObjectUUID
		filePointer.LatestFileObjectUUID = originalFileObjectUUID

		// Fix FileObject
		fileObject.FileUUID = fileUUID
		fileObject.NextFileObjectUUID = nextFileObjectUUID

		// Get hashedFilenameUUID
		hashedFilenameUUID, err := getHashedFilenameUUID(filename)
		if err != nil {
			return err
		}

		// Fix filedata and userdata
		userdata.FilesOwned[hashedFilenameUUID] = fileOwnerInfoUUID
		filedata.Content = content
		err = WriteUpdatedUserToDatastore(*userdata)
		if err != nil {
			return err
		}

		// Derive symmetricKey and HMACKey to filePointer, fileObject and file of file
		filePointerSymmetricKey, fileObjectSymmetricKey, fileSymmetricKey := DeriveFileSymmetricKey(fileKeys.FileSymmetricKey)
		filePointerHMACKey, fileObjectHMACKey, fileHMACKey := DeriveFileHMACKey(fileKeys.FileHMACKey)

		// Derive symmetricKey and HMACKey to fileOwnerInfo of file
		fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey, err := DeriveFileOwnerInfoSymmetricKeyAndHMACKey(filename, *userdata)
		if err != nil {
			return err
		}

		// Write fileOwnerInfo to Datastore
		err = WriteToDatastore(fileOwnerInfoUUID, fileOwnerInfo, fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey)
		if err != nil {
			return err
		}

		// Write fileKeys to Datastore
		err = WriteToDatastore(fileKeysUUID, fileKeys, fileOwnerInfo.FileKeysSymmetricKey, fileOwnerInfo.FileKeysHMACKey)
		if err != nil {
			return err
		}

		// Write filePointer to Datastore
		err = WriteToDatastore(filePointerUUID, filePointer, filePointerSymmetricKey, filePointerHMACKey)
		if err != nil {
			return err
		}

		// Write fileObject to Datastore
		err = WriteToDatastore(originalFileObjectUUID, fileObject, fileObjectSymmetricKey, fileObjectHMACKey)
		if err != nil {
			return err
		}

		// Write filedata to Datastore
		err = WriteToDatastore(fileUUID, filedata, fileSymmetricKey, fileHMACKey)
		if err != nil {
			return err
		}

	} else {

		// Check if user is the owner
		if isUserOwner(filename, *userdata) {

			// Get keys and UUID of file
			storedFileSymmetricKey, storedFileHMACKey, storedFilePointerUUID, err := getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileOwned(filename, *userdata)
			if err != nil {
				return err
			}

			// Derive symmetricKey and HMACKey to filePointer, fileObject and file of file
			filePointerSymmetricKey, fileObjectSymmetricKey, fileSymmetricKey := DeriveFileSymmetricKey(storedFileSymmetricKey)
			filePointerHMACKey, fileObjectHMACKey, fileHMACKey := DeriveFileHMACKey(storedFileHMACKey)

			originalFileObjectUUID, err := getOriginalFileObjectUUID(filename, *userdata)
			if err != nil {
				return err
			}

			originalFileUUID, err := getOriginalFileUUID(filename, *userdata)
			if err != nil {
				return err
			}

			nextFileObjectUUID := uuid.New()

			filedata.Content = content

			// Write filedata to Datastore
			err = WriteToDatastore(originalFileUUID, filedata, fileSymmetricKey, fileHMACKey)
			if err != nil {
				return err
			}

			// Update OriginalFileObject
			err = setOriginalFileObject(filename, *userdata, originalFileObjectUUID, originalFileUUID, nextFileObjectUUID, fileObjectSymmetricKey, fileObjectHMACKey)
			if err != nil {
				return err
			}

			// Update FilePointer
			err = setFilePointer(filename, *userdata, storedFilePointerUUID, originalFileObjectUUID, originalFileObjectUUID, filePointerSymmetricKey, filePointerHMACKey)
			if err != nil {
				return err
			}
		}

		// Check if file is shared with user
		if isFileSharedWithUser(filename, *userdata) {

			// Get keys and UUID of file
			storedFileSymmetricKey, storedFileHMACKey, storedFilePointerUUID, err := getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileShared(filename, *userdata)
			if err != nil {
				return err
			}

			// Derive symmetricKey and HMACKey to filePointer, fileObject and file of file
			filePointerSymmetricKey, fileObjectSymmetricKey, fileSymmetricKey := DeriveFileSymmetricKey(storedFileSymmetricKey)
			filePointerHMACKey, fileObjectHMACKey, fileHMACKey := DeriveFileHMACKey(storedFileHMACKey)

			originalFileObjectUUID, err := getOriginalFileObjectUUID(filename, *userdata)
			if err != nil {
				return err
			}

			originalFileUUID, err := getOriginalFileUUID(filename, *userdata)
			if err != nil {
				return err
			}

			nextFileObjectUUID := uuid.New()

			filedata.Content = content

			// Write filedata to Datastore
			err = WriteToDatastore(originalFileUUID, filedata, fileSymmetricKey, fileHMACKey)
			if err != nil {
				return err
			}

			// Update OriginalFileObject
			err = setOriginalFileObject(filename, *userdata, originalFileObjectUUID, originalFileUUID, nextFileObjectUUID, fileObjectSymmetricKey, fileObjectHMACKey)
			if err != nil {
				return err
			}

			// Update FilePointer
			err = setFilePointer(filename, *userdata, storedFilePointerUUID, originalFileObjectUUID, originalFileObjectUUID, filePointerSymmetricKey, filePointerHMACKey)
			if err != nil {
				return err
			}
		}

		return err
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	var appendedFiledata File
	var storedFileSymmetricKey []byte
	var storedFileHMACKey []byte
	var storedFilePointerUUID uuid.UUID

	// Update userdata in case of multiple sessions
	userdata, err = UpdateUser(userdata.Username, userdata.HashedPassword)
	if err != nil {
		return err
	}

	// Throw error if file does not exist in userdata.FilesOwned or userdata.FilesShared
	if !checkIfFilenameExists(filename, *userdata) {
		return errors.New(strings.ToTitle("Filename does not exist."))
	}

	if isUserOwner(filename, *userdata) {
		// Get keys and UUID of file
		storedFileSymmetricKey, storedFileHMACKey, storedFilePointerUUID, err = getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileOwned(filename, *userdata)
		if err != nil {
			return err
		}
	} else if isFileSharedWithUser(filename, *userdata) {
		// Get keys and UUID of file
		storedFileSymmetricKey, storedFileHMACKey, storedFilePointerUUID, err = getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileShared(filename, *userdata)
		if err != nil {
			return err
		}
	} else {
		return errors.New(strings.ToTitle("User does not have access to append to this file."))
	}

	// Derive symmetricKey and HMACKey to filePointer, fileObject and file of file
	filePointerSymmetricKey, fileObjectSymmetricKey, fileSymmetricKey := DeriveFileSymmetricKey(storedFileSymmetricKey)
	filePointerHMACKey, fileObjectHMACKey, fileHMACKey := DeriveFileHMACKey(storedFileHMACKey)

	originalFileObjectUUID, err := getOriginalFileObjectUUID(filename, *userdata)
	if err != nil {
		return err
	}

	appendedFileObjectUUID, err := getNextFileObjectUUID(filename, *userdata)
	if err != nil {
		return err
	}

	appendedFileUUID := uuid.New()
	appendedNextFileObjectUUID := uuid.New()

	// Set attributes in appendedFiledata
	appendedFiledata.Content = content

	// Writes appendedFiledata to Datastore
	err = WriteToDatastore(appendedFileUUID, appendedFiledata, fileSymmetricKey, fileHMACKey)
	if err != nil {
		return err
	}

	// Update OriginalFileObject
	err = setNextFileObject(filename, *userdata, appendedFileObjectUUID, appendedFileUUID, appendedNextFileObjectUUID, fileObjectSymmetricKey, fileObjectHMACKey)
	if err != nil {
		return err
	}

	// Update FilePointer
	err = setFilePointer(filename, *userdata, storedFilePointerUUID, originalFileObjectUUID, appendedFileObjectUUID, filePointerSymmetricKey, filePointerHMACKey)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	var fileUUID uuid.UUID
	var storedFileSymmetricKey []byte
	var storedFileHMACKey []byte

	// Update userdata in case of multiple sessions
	userdata, err = UpdateUser(userdata.Username, userdata.HashedPassword)
	if err != nil {
		return nil, err
	}

	// Throw error if file does not exist in userdata.FilesOwned or userdata.FilesShared
	if !checkIfFilenameExists(filename, *userdata) {
		return nil, errors.New(strings.ToTitle("User does not have access to file."))
	} else {
		access, err := checkIfFileKeysIsSharedWithUser(filename, userdata.Username, *userdata)
		if err != nil {
			return nil, err
		}
		if !access {
			return nil, errors.New(strings.ToTitle("User does not have access to load file."))
		}

		fileUUID, err = getOriginalFileUUID(filename, *userdata)
		if err != nil {
			return nil, err
		}
	}

	// Check if file exists in Datastore
	_, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return nil, err
	}

	if isUserOwner(filename, *userdata) {
		// Get keys and UUID of file
		storedFileSymmetricKey, storedFileHMACKey, _, err = getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileOwned(filename, *userdata)
		if err != nil {
			return nil, err
		}
	} else if isFileSharedWithUser(filename, *userdata) {
		// Get keys and UUID of file
		storedFileSymmetricKey, storedFileHMACKey, _, err = getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileShared(filename, *userdata)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	// Derive symmetricKey and HMACKey to filePointer, fileObject and file of file
	_, fileObjectSymmetricKey, fileSymmetricKey := DeriveFileSymmetricKey(storedFileSymmetricKey)
	_, fileObjectHMACKey, fileHMACKey := DeriveFileHMACKey(storedFileHMACKey)

	originalFileObjectUUID, err := getOriginalFileObjectUUID(filename, *userdata)
	if err != nil {
		return nil, err
	}

	latestFileObjectUUID, err := getLatestFileObjectUUID(filename, *userdata)
	if err != nil {
		return nil, err
	}

	fileContent, err := getFileContentRecursively(filename, originalFileObjectUUID, latestFileObjectUUID, fileObjectSymmetricKey, fileObjectHMACKey, fileSymmetricKey, fileHMACKey, *userdata)
	if err != nil {
		return nil, err
	}

	return fileContent, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// Update userdata in case of multiple sessions
	userdata, err = UpdateUser(userdata.Username, userdata.HashedPassword)
	if err != nil {
		return uuid.Nil, err
	}

	if !checkIfFilenameExists(filename, *userdata) {
		return uuid.Nil, errors.New(strings.ToTitle("User does not have access to the file and can therefore not share the file."))
	}

	var invitationKeys InvitationKeys
	var invitation Invitation

	// Check if user is owner of the file, if not, the user cannot invite others
	if isUserOwner(filename, *userdata) {

		var fileOwnerInfo FileOwnerInfo
		fileOwnerInfoptr := &fileOwnerInfo

		// Derive fileOwnerInfoSymmetricKey and fileOwnerInfoHMACKey
		fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey, err := DeriveFileOwnerInfoSymmetricKeyAndHMACKey(filename, *userdata)
		if err != nil {
			return uuid.Nil, err
		}

		// Get hashedFilenameUUID
		hashedFilenameUUID, err := getHashedFilenameUUID(filename)
		if err != nil {
			return uuid.Nil, err
		}

		// Get fileOwnerInfo of the file
		fileOwnerInfoUUID := userdata.FilesOwned[hashedFilenameUUID]
		storedFileOwnerInfoMarshal, err := ReadFromDatastore(fileOwnerInfoUUID, fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey)
		if err != nil {
			return uuid.Nil, err
		}
		err = json.Unmarshal(storedFileOwnerInfoMarshal, fileOwnerInfoptr)
		if err != nil {
			return uuid.Nil, err
		}

		// Get keys of FileKeys from fileOwnerInfo
		fileKeysSymmetricKey := fileOwnerInfo.FileKeysSymmetricKey
		fileKeysHMACKey := fileOwnerInfo.FileKeysHMACKey
		fileKeysUUID := fileOwnerInfo.FileKeysUUID

		// Create invitationUUID
		invitationSalt := fileOwnerInfo.InvitationSalt
		invitationKeysUUID, err := deriveInvitationKeysUUID(recipientUsername, invitationSalt)
		invitationUUID := uuid.New()

		// Set values of invitationKeys
		invitationKeys.SK = userlib.RandomBytes(lengthOfKey)
		invitationKeys.HK = userlib.RandomBytes(lengthOfKey)
		invitationKeys.ID = invitationUUID

		// Set values of invitation
		invitation.FileKeysSymmetricKey = fileKeysSymmetricKey
		invitation.FileKeysHMACKey = fileKeysHMACKey
		invitation.FileKeysUUID = fileKeysUUID
		invitation.InvitationSalt = fileOwnerInfo.InvitationSalt

		// Sign, encrypt and write invitationKeys to Datastore
		err = SignEncryptAndWriteInvitationKeysToDatastore(invitationKeysUUID, invitationKeys, recipientUsername, *userdata)
		if err != nil {
			return uuid.Nil, err
		}

		// Encrypt and write invitation to Datastore
		err = WriteToDatastore(invitationUUID, invitation, invitationKeys.SK, invitationKeys.HK)
		if err != nil {
			return uuid.Nil, err
		}

		return invitationKeysUUID, nil

	} else {

		// Get hashedFilenameUUID
		hashedFilenameUUID, err := getHashedFilenameUUID(filename)
		if err != nil {
			return uuid.Nil, err
		}

		// Get fileOwnerInfo of the file
		sendersInvitationKeysUUID := userdata.FilesShared[hashedFilenameUUID]
		_, sendersInvitation, err := VerifyDecryptAndReadInvitationFromDatastore(sendersInvitationKeysUUID, *userdata)
		if err != nil {
			return uuid.Nil, err
		}

		// Get keys of FileKeys from sendersInvitation
		fileKeysSymmetricKey := sendersInvitation.FileKeysSymmetricKey
		fileKeysHMACKey := sendersInvitation.FileKeysHMACKey
		fileKeysUUID := sendersInvitation.FileKeysUUID

		// Create invitationUUID
		invitationSalt := sendersInvitation.InvitationSalt
		invitationKeysUUID, err := deriveInvitationKeysUUID(recipientUsername, invitationSalt)
		invitationUUID := uuid.New()

		// Set vales of invitationKeys
		invitationKeys.SK = userlib.RandomBytes(lengthOfKey)
		invitationKeys.HK = userlib.RandomBytes(lengthOfKey)
		invitationKeys.ID = invitationUUID

		// Set values of invitation
		invitation.FileKeysSymmetricKey = fileKeysSymmetricKey
		invitation.FileKeysHMACKey = fileKeysHMACKey
		invitation.FileKeysUUID = fileKeysUUID
		invitation.InvitationSalt = sendersInvitation.InvitationSalt

		// Sign, encrypt and write invitationKeys to Datastore
		err = SignEncryptAndWriteInvitationKeysToDatastore(invitationKeysUUID, invitationKeys, recipientUsername, *userdata)
		if err != nil {
			return uuid.Nil, err
		}

		// Encrypt and write invitation to Datastore
		err = WriteToDatastore(invitationUUID, invitation, invitationKeys.SK, invitationKeys.HK)
		if err != nil {
			return uuid.Nil, err
		}

		return invitationKeysUUID, nil
	}
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {

	// Update userdata in case of multiple sessions
	userdata, err = UpdateUser(userdata.Username, userdata.HashedPassword)
	if err != nil {
		return err
	}

	// Throw error if filename exists already
	if checkIfFilenameExists(filename, *userdata) {
		return errors.New(strings.ToTitle("User does not have access to the file and can therefore not accept the invitation."))
	}

	// Throw error if user has already accepted invitation before
	err = checkIfUserAcceptedInvitationAlready(invitationPtr, *userdata)
	if err != nil {
		return err
	}

	// Throw error if invitation is not actually sent by senderUsername
	err = checkIfSenderIsAuthentic(invitationPtr, senderUsername)
	if err != nil {
		return err
	}

	// Check if invitation exists
	_, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New(strings.ToTitle("Invitation does not exist."))
	}

	// Get hashedFilenameUUID
	hashedFilenameUUID, err := getHashedFilenameUUID(filename)
	if err != nil {
		return err
	}

	// Add invitationPtr to userdata.FilesShared
	userdata.FilesShared[hashedFilenameUUID] = invitationPtr
	err = WriteUpdatedUserToDatastore(*userdata)
	if err != nil {
		return err
	}

	// Update fileKeys.UsersSharedWith
	recipientUsername := userdata.Username
	err = addSharingToFileKeys(filename, senderUsername, recipientUsername, *userdata)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {

	// Update userdata in case of multiple sessions
	userdata, err = UpdateUser(userdata.Username, userdata.HashedPassword)
	if err != nil {
		return err
	}

	// Throw error if user is not Owner
	if !isUserOwner(filename, *userdata) {
		return errors.New(strings.ToTitle("User is not the owner of the file and can therefore not revoke access."))
	}

	// Throw error if file is not shared with user
	ok, err := checkIfFileKeysIsSharedWithUser(filename, recipientUsername, *userdata)
	if !ok {
		return err
	}
	if err != nil {
		return err
	}

	// ownerUsername := userdata.Username
	var fileOwnerInfo FileOwnerInfo
	var fileKeys FileKeys
	fileOwnerInfoptr := &fileOwnerInfo
	fileKeysptr := &fileKeys

	// Derive fileOwnerInfoSymmetricKey and fileOwnerInfoHMACKey
	fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey, err := DeriveFileOwnerInfoSymmetricKeyAndHMACKey(filename, *userdata)
	if err != nil {
		return err
	}

	// Get hashedFilenameUUID
	hashedFilenameUUID, err := getHashedFilenameUUID(filename)
	if err != nil {
		return err
	}

	// Get fileOwnerInfo of file
	fileOwnerInfoUUID := userdata.FilesOwned[hashedFilenameUUID]
	storedFileOwnerInfoMarshal, err := ReadFromDatastore(fileOwnerInfoUUID, fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(storedFileOwnerInfoMarshal, fileOwnerInfoptr)
	if err != nil {
		return err
	}

	// Get values from fileOwnerInfo
	storedFileKeysSymmetricKey := fileOwnerInfo.FileKeysSymmetricKey
	storedFileKeysHMACKey := fileOwnerInfo.FileKeysHMACKey
	storedFileKeysUUID := fileOwnerInfo.FileKeysUUID

	// Get fileKeys of file
	storedFileKeysMarshal, err := ReadFromDatastore(storedFileKeysUUID, storedFileKeysSymmetricKey, storedFileKeysHMACKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(storedFileKeysMarshal, fileKeysptr)
	if err != nil {
		return err
	}

	// Get values from fileKeys
	storedFileSymmetricKey := fileKeys.FileSymmetricKey
	storedFileHMACKey := fileKeys.FileHMACKey

	// Get storedOriginalFileObjectUUID from filePointer
	storedFilePointerUUID, err := getFilePointerUUID(filename, *userdata)
	if err != nil {
		return err
	}
	storedOriginalFileObjectUUID, err := getOriginalFileObjectUUID(filename, *userdata)
	if err != nil {
		return err
	}
	storedLatestFileObjectUUID, err := getLatestFileObjectUUID(filename, *userdata)
	if err != nil {
		return err
	}

	// Remove revoked users from fileKeys.UsersSharedWith
	err = removeAccess(filename, recipientUsername, storedFileKeysSymmetricKey, storedFileKeysHMACKey, *userdata)
	if err != nil {
		return err
	}

	// Create new keys for FileKeys (keys to FilePointer and Files)
	updatedFileSymmetricKey := userlib.RandomBytes(lengthOfKey)
	updatedFileHMACKey := userlib.RandomBytes(lengthOfKey)
	updatedFilePointerUUID := uuid.New()

	// Create new keys for Invitations (keys to FileKeys)
	updatedFileKeysSymmetricKey := userlib.RandomBytes(lengthOfKey)
	updatedFileKeysHMACKey := userlib.RandomBytes(lengthOfKey)
	updatedFileKeysUUID := uuid.New()

	// Update Files, FileObjects and FilePointer (change, encrypt and store at different UUIDs, merge Files to one updated File)
	err = updateFiles(filename, updatedFilePointerUUID, updatedFileSymmetricKey, updatedFileHMACKey, storedFileSymmetricKey, storedFileHMACKey, *userdata)
	if err != nil {
		return err
	}

	// Update FileKeys (change, encrypt and store at a different UUID)
	err = UpdateFileKeys(filename, updatedFilePointerUUID, updatedFileKeysUUID, storedFileKeysUUID, updatedFileSymmetricKey, updatedFileHMACKey, updatedFileKeysSymmetricKey, updatedFileKeysHMACKey, storedFileKeysSymmetricKey, storedFileKeysHMACKey, *userdata)
	if err != nil {
		return err
	}

	// Update invitations of users who still have access (Overwrites all invitations with access)
	err = updateInvitations(filename, fileOwnerInfoUUID, updatedFileKeysUUID, updatedFileKeysSymmetricKey, updatedFileKeysHMACKey, *userdata)
	if err != nil {
		return err
	}

	// Update FileOwnerInfo
	err = updateFileOwnerInfo(filename, fileOwnerInfoUUID, updatedFileKeysUUID, updatedFileKeysSymmetricKey, updatedFileKeysHMACKey, *userdata)
	if err != nil {
		return err
	}

	// Delete old FileKeys from Datastore
	deleteOldFileKeys(storedFileKeysUUID)

	// Delete old Files (FilePointer, FileObjects, Files) from Datastore
	err = deleteOldFiles(filename, storedFilePointerUUID, storedOriginalFileObjectUUID, storedLatestFileObjectUUID, storedFileSymmetricKey, storedFileHMACKey, *userdata)
	if err != nil {
		return err
	}

	return nil
}

// ------------ HELPING FUNCTIONS ------------

// Checks if a user exists in Keystore
func checkIfUserExists(username string) (exists bool) {
	usernamePublicKeyID := username + "PublicKey"
	usernameVerificationKeyID := username + "VerificationKey"

	_, ok1 := userlib.KeystoreGet(usernamePublicKeyID)
	_, ok2 := userlib.KeystoreGet(usernameVerificationKeyID)
	return ok1 && ok2
}

func getHashedFilenameUUID(filename string) (returnedHashedFilenameUUID uuid.UUID, err error) {
	hashedFilename := userlib.Hash([]byte(filename + filenamePadding))[:lengthOfHash]
	hashedFilenameUUID, err := uuid.FromBytes(hashedFilename)
	if err != nil {
		return uuid.Nil, err
	}
	return hashedFilenameUUID, nil
}

// Checks if requested filename exists in userdata.FilesOwned
func isUserOwner(filename string, userdata User) (ok bool) {

	// Get hashedFilenameUUID
	hashedFilenameUUID, err := getHashedFilenameUUID(filename)
	if err != nil {
		return false
	}

	for userHashedFilenameUUID, _ := range userdata.FilesOwned {
		if userHashedFilenameUUID == hashedFilenameUUID {
			return true
		}
	}
	return false
}

// Checks if requested filename exists in userdata.FilesShared
func isFileSharedWithUser(filename string, userdata User) (ok bool) {

	// Get hashedFilenameUUID
	hashedFilenameUUID, err := getHashedFilenameUUID(filename)
	if err != nil {
		return false
	}

	for userHashedFilenameUUID, _ := range userdata.FilesShared {
		if userHashedFilenameUUID == hashedFilenameUUID {
			return true
		}
	}
	return false
}

// Checks if request filename exists in userdata.FilesOwned or userdata.FilesShared
func checkIfFilenameExists(filename string, userdata User) (ok bool) {
	return isUserOwner(filename, userdata) || isFileSharedWithUser(filename, userdata)
}

// Checks if HMAC is valid
func isValidHMAC(HMACKey []byte, storedHMACEncryptedDataMarshal []byte) (ok bool) {
	storedHMAC := storedHMACEncryptedDataMarshal[len(storedHMACEncryptedDataMarshal)-lengthOfMAC:]

	storedEncryptedDataMarshal := storedHMACEncryptedDataMarshal[:len(storedHMACEncryptedDataMarshal)-lengthOfMAC]

	HMAC, err := userlib.HMACEval(HMACKey[:lengthOfKey], storedEncryptedDataMarshal)
	if err != nil {
		return false
	}

	ok = userlib.HMACEqual(storedHMAC, HMAC)

	return ok
}

// Derives symmetricKey of File
func DeriveFileSymmetricKey(symmetricKey []byte) (returnedFilePointerSymmetricKey []byte, returnedFileObjectSymmetricKey []byte, returnedFileSymmetricKey []byte) {

	// Hash symmetricKey to encrypt FilePointer, FileObject and File
	filePointerSymmetricKey := symmetricKey
	fileObjectSymmetricKey := userlib.Hash(filePointerSymmetricKey)
	fileSymmetricKey := userlib.Hash(fileObjectSymmetricKey)

	return filePointerSymmetricKey, fileObjectSymmetricKey, fileSymmetricKey
}

// Derives HMACKey of file
func DeriveFileHMACKey(HMACKey []byte) (returnedFilePointerHMACKey []byte, returnedFileObjectHMACKey []byte, returnedFileHMACKey []byte) {

	// Hash HMACKey to encrypt FilePointer, FileObject and File
	filePointerHMACKey := HMACKey
	fileObjectHMACKey := userlib.Hash(filePointerHMACKey)
	fileHMACKey := userlib.Hash(fileObjectHMACKey)

	return filePointerHMACKey, fileObjectHMACKey, fileHMACKey
}

// Derives symmetricKey and HMACKey of fileOwnerInfo
func DeriveFileOwnerInfoSymmetricKeyAndHMACKey(filename string, userdata User) (returnedSymmetricKey []byte, returnedHMACKey []byte, err error) {

	// Derive symmetricKey to fileOwnerInfo of file
	fileOwnerInfoSymmetricKey, err := userlib.HashKDF(userdata.SymmetricKey, []byte(filename+"SymmetricKey"))
	if err != nil {
		return nil, nil, err
	}

	// Derive HMACKey to fileOwnerInfo of file
	HMAC, err := userlib.HashKDF(userdata.SymmetricKey, []byte(filename+"HMACKey"))
	if err != nil {
		return nil, nil, err
	}
	fileOwnerInfoHMACKey := HMAC[:lengthOfKey]

	return fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey, nil
}

func EncryptFileWithSymmetricKeyAndHMAC(fileObject interface{}, symmetricKey []byte, HMACKey []byte) (encryptedData []byte, err error) {
	fileObjectMarshal, err := json.Marshal(fileObject)
	if err != nil {
		return nil, err
	}
	encryptedFileObjectMarshal := userlib.SymEnc(symmetricKey[:lengthOfKey], userlib.RandomBytes(lengthOfKey), fileObjectMarshal)
	HMAC, err := userlib.HMACEval(HMACKey, encryptedFileObjectMarshal)
	if err != nil {
		return nil, err
	}
	HMACEncryptedFileObjectMarshal := append(encryptedFileObjectMarshal, HMAC...)
	return HMACEncryptedFileObjectMarshal, err
}

func DecryptAndRemoveHMACFromFile(storedHMACEncryptedFiledataMarshal []byte, symmetricKey []byte, HMACKey []byte) (filedataMarshal []byte, err error) {
	if !isValidHMAC(HMACKey, storedHMACEncryptedFiledataMarshal) {
		return nil, errors.New(strings.ToTitle("Invalid MAC when decrypting file from Datastore"))
	}
	storedEncryptedFiledataMarshal := storedHMACEncryptedFiledataMarshal[:len(storedHMACEncryptedFiledataMarshal)-lengthOfMAC]
	storedFiledataMarshal := userlib.SymDec(symmetricKey[:lengthOfKey], storedEncryptedFiledataMarshal)
	return storedFiledataMarshal, err
}

func WriteToDatastore(fileUUID uuid.UUID, fileObject interface{}, symmetricKey []byte, HMACKey []byte) (err error) {
	HMACEncryptedFileObjectMarshal, err := EncryptFileWithSymmetricKeyAndHMAC(fileObject, symmetricKey, HMACKey[:lengthOfKey])
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileUUID, HMACEncryptedFileObjectMarshal)
	return nil
}

func ReadFromDatastore(fileUUID uuid.UUID, symmetricKey []byte, HMACKey []byte) (bytes []byte, err error) {
	storedHMACEncryptedFiledataMarshal, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("Something went wrong when trying to read from Datastore"))
	}
	storedFiledataMarshal, err := DecryptAndRemoveHMACFromFile(storedHMACEncryptedFiledataMarshal, symmetricKey, HMACKey[:lengthOfKey])
	if err != nil {
		return nil, err
	}
	return storedFiledataMarshal, nil
}

func EncryptInvitationWithPublicKeyAndSign(invitationKeysUUID uuid.UUID, invitationKeys InvitationKeys, recipientPublicKey userlib.PKEEncKey, senderSigningKey userlib.DSSignKey) (returnedSignedEncryptedInvitationKeysMarshal []byte, err error) {

	// Marshal the invitation
	invitationKeysMarshal, err := json.Marshal(invitationKeys)
	if err != nil {
		return nil, err
	}

	// Public Key encrypt the invitationMarshal
	encryptedInvitationKeysMarshal, err := userlib.PKEEnc(recipientPublicKey, invitationKeysMarshal)
	if err != nil {
		return nil, err
	}

	// Create signature of encrypted invitationMarshal (256 byte signature)
	invitationKeysSignature, err := userlib.DSSign(senderSigningKey, encryptedInvitationKeysMarshal)

	// Sign the encrypted invitationMarshal
	signedEncryptedInvitationKeysMarshal := append(encryptedInvitationKeysMarshal, invitationKeysSignature...)

	return signedEncryptedInvitationKeysMarshal, nil
}

func VerifySignatureAndDecryptInvitation(invitationKeysUUID uuid.UUID, storedSignedEncryptedInvitationKeysMarshal []byte, recipient User) (returnedInvitationKeys *InvitationKeys, returnedInvitation *Invitation, err error) {

	var invitationKeys InvitationKeys
	var invitation Invitation
	invitationKeysptr := &invitationKeys
	invitationptr := &invitation

	// Split invitationKeysMarshal into a public-key encrypted part and a signed part
	storedEncryptedInvitationKeysMarshal := storedSignedEncryptedInvitationKeysMarshal[:len(storedSignedEncryptedInvitationKeysMarshal)-lengthOfSHAKey]

	// Decrypt and unmarshal Public-Key encryption using recipientSecretKey
	recipientPrivateKey := recipient.PrivateKey
	storedInvitationKeysMarshal, err := userlib.PKEDec(recipientPrivateKey, storedEncryptedInvitationKeysMarshal)
	if err != nil {
		return nil, nil, err
	}
	err = json.Unmarshal(storedInvitationKeysMarshal, &invitationKeysptr)
	if err != nil {
		return nil, nil, err
	}

	// Decrypt and unmarshal invitation using keys from invitationKeys
	storedInvitationMarshal, err := ReadFromDatastore(invitationKeys.ID, invitationKeys.SK, invitationKeys.HK[:lengthOfKey])
	if err != nil {
		return nil, nil, err
	}
	err = json.Unmarshal(storedInvitationMarshal, invitationptr)
	if err != nil {
		return nil, nil, err
	}

	// Get senderUsername
	senderUsername := invitation.SenderUsername

	// Verify that the signature of the sender is authentic
	err = checkIfSenderIsAuthentic(invitationKeysUUID, senderUsername)
	if err != nil {
		return nil, nil, err
	}

	return invitationKeysptr, invitationptr, nil
}

func SignEncryptAndWriteInvitationKeysToDatastore(invitationKeysUUID uuid.UUID, invitationKeys InvitationKeys, recipientUsername string, sender User) (err error) {

	// Get recipientPublicKey from Keystore
	recipientPublicKey, ok := userlib.KeystoreGet(recipientUsername + "PublicKey")
	if !ok {
		return err
	}

	// Get senderSigningKey from sender
	senderSigningKey := sender.SigningKey

	// Encrypt and sign invitation
	signedEncryptedInvitationKeysMarshal, err := EncryptInvitationWithPublicKeyAndSign(invitationKeysUUID, invitationKeys, recipientPublicKey, senderSigningKey)
	if err != nil {
		return err
	}

	// Store encrypted and signed invitation to Datastore
	userlib.DatastoreSet(invitationKeysUUID, signedEncryptedInvitationKeysMarshal)

	return nil
}

func VerifyDecryptAndReadInvitationFromDatastore(invitationKeysUUID uuid.UUID, recipient User) (returnedInvitationKeys *InvitationKeys, returnedInvitation *Invitation, err error) {

	// Get storedSignedEncryptedInvitationMarshal from Datastore
	storedSignedEncryptedInvitationKeysMarshal, ok := userlib.DatastoreGet(invitationKeysUUID)
	if !ok {
		return nil, nil, err
	}

	// Verify signature and decrypt invitation
	invitationKeys, invitation, err := VerifySignatureAndDecryptInvitation(invitationKeysUUID, storedSignedEncryptedInvitationKeysMarshal, recipient)
	if err != nil {
		return nil, nil, err
	}

	return invitationKeys, invitation, nil
}

// Get FileOwnerInfo of requested file
func getFileOwnerInfoUUID(filename string, userdata User) (returnedFileOwnerInfoUUID uuid.UUID, err error) {

	// Check if file is owned by user
	if !isUserOwner(filename, userdata) {
		return uuid.Nil, err
	}

	// Get hashedFilenameUUID
	hashedFilenameUUID, err := getHashedFilenameUUID(filename)
	if err != nil {
		return uuid.Nil, err
	}

	// Get invitationUUID from userdata.FilesShared
	fileOwnerInfoUUID := userdata.FilesOwned[hashedFilenameUUID]
	return fileOwnerInfoUUID, nil

}

// Get FileOwnerInfo of requested file
func getFileOwnerInfo(filename string, userdata User) (returnedFileOwnerInfo *FileOwnerInfo, err error) {
	var fileOwnerInfo FileOwnerInfo
	fileOwnerInfoptr := &fileOwnerInfo

	fileOwnerInfoUUID, err := getFileOwnerInfoUUID(filename, userdata)
	if err != nil {
		return nil, err
	}

	// Derive fileOwnerInfoSymmetricKey and fileOwnerInfoHMACKey
	fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey, err := DeriveFileOwnerInfoSymmetricKeyAndHMACKey(filename, userdata)
	if err != nil {
		return nil, err
	}

	// Decrypt fileOwnerInfoMarhsal and store in fileOwnerInfoptr
	storedFileOwnerInfoMarshal, err := ReadFromDatastore(fileOwnerInfoUUID, fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey[:16])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(storedFileOwnerInfoMarshal, fileOwnerInfoptr)
	if err != nil {
		return nil, err
	}

	return fileOwnerInfoptr, nil
}

// Get InvitationUUID of requested file
func getInvitationKeysUUID(filename string, userdata User) (returnedInvitationUUID uuid.UUID, err error) {

	// Check if file is shared with user
	if !isFileSharedWithUser(filename, userdata) {
		return uuid.Nil, err
	}

	// Get hashedFilenameUUID
	hashedFilenameUUID, err := getHashedFilenameUUID(filename)
	if err != nil {
		return uuid.Nil, err
	}

	// Get invitationUUID from userdata.FilesShared
	invitationKeysUUID := userdata.FilesShared[hashedFilenameUUID]
	return invitationKeysUUID, nil
}

// Get Invitation of requested file
func getInvitationKeys(filename string, userdata User) (returnedInvitationKeys *InvitationKeys, err error) {

	invitationKeysUUID, err := getInvitationKeysUUID(filename, userdata)
	if err != nil {
		return nil, err
	}

	// Decrypt invitation and store in invitationptr
	invitationKeysptr, _, err := VerifyDecryptAndReadInvitationFromDatastore(invitationKeysUUID, userdata)
	if err != nil {
		return nil, err
	}

	return invitationKeysptr, nil
}

// Get InvitationUUID of requested file
func getInvitationUUID(filename string, userdata User) (returnedInvitationUUID uuid.UUID, err error) {

	invitationKeys, err := getInvitationKeys(filename, userdata)
	if err != nil {
		return uuid.Nil, err
	}

	// Get invitationUUID from invitationKeys
	invitationUUID := invitationKeys.ID

	return invitationUUID, nil
}

// Get Invitation of requested file
func getInvitation(filename string, userdata User) (returnedInvitation *Invitation, err error) {

	invitationKeysUUID, err := getInvitationKeysUUID(filename, userdata)
	if err != nil {
		return nil, err
	}

	// Decrypt invitation and store in invitationptr
	_, invitationptr, err := VerifyDecryptAndReadInvitationFromDatastore(invitationKeysUUID, userdata)
	if err != nil {
		return nil, err
	}

	return invitationptr, nil
}

// Gets FileKeysUUID of requested file
func getFileKeysUUID(filename string, userdata User) (returnedFileKeysUUID uuid.UUID, err error) {
	if isUserOwner(filename, userdata) {

		// Get fileOwnerInfo and return fileOwnerInfo.FileKeysUUID
		fileOwnerInfo, err := getFileOwnerInfo(filename, userdata)
		if err != nil {
			return uuid.Nil, err
		}
		fileKeysUUID := fileOwnerInfo.FileKeysUUID
		return fileKeysUUID, nil

	}
	if isFileSharedWithUser(filename, userdata) {

		// Decrypt and get invitation.FileKeysUUID
		invitation, err := getInvitation(filename, userdata)
		if err != nil {
			return uuid.Nil, err
		}
		fileKeysUUID := invitation.FileKeysUUID
		return fileKeysUUID, nil

	}
	return uuid.Nil, err
}

// Gets FileKeys of requested file
func getFileKeys(filename string, userdata User) (returnedFileKeys *FileKeys, err error) {

	var fileKeys FileKeys
	fileKeysptr := &fileKeys

	if isUserOwner(filename, userdata) {

		// Get fileOwnerInfo
		fileOwnerInfo, err := getFileOwnerInfo(filename, userdata)
		if err != nil {
			return nil, err
		}
		fileKeysSymmetricKey := fileOwnerInfo.FileKeysSymmetricKey
		fileKeysHMACKey := fileOwnerInfo.FileKeysHMACKey
		fileKeysUUID := fileOwnerInfo.FileKeysUUID

		// Decrypt userFileKeys and store in &userFileKeysptr
		storedFileKeysMarshal, err := ReadFromDatastore(fileKeysUUID, fileKeysSymmetricKey, fileKeysHMACKey[:lengthOfKey])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(storedFileKeysMarshal, fileKeysptr)
		if err != nil {
			return nil, err
		}

		return fileKeysptr, nil
	}
	if isFileSharedWithUser(filename, userdata) {

		// Decrypt and get invitation.FileKeysUUID
		invitation, err := getInvitation(filename, userdata)
		if err != nil {
			return nil, err
		}
		fileKeysSymmetricKey := invitation.FileKeysSymmetricKey
		fileKeysHMACKey := invitation.FileKeysHMACKey
		fileKeysUUID := invitation.FileKeysUUID

		// Decrypt userFileKeys and store in &userFileKeysptr
		storedFileKeysMarshal, err := ReadFromDatastore(fileKeysUUID, fileKeysSymmetricKey, fileKeysHMACKey[:lengthOfKey])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(storedFileKeysMarshal, fileKeysptr)
		if err != nil {
			return nil, err
		}

		return fileKeysptr, nil

	}
	return nil, err
}

// Gets FilePointerUUID of requested file
func getFilePointerUUID(filename string, userdata User) (returnedFilePointerUUID uuid.UUID, err error) {

	// Decrypt and get invitation.FileKeysUUID
	fileKeys, err := getFileKeys(filename, userdata)
	if err != nil {
		return uuid.Nil, err
	}
	filePointerUUID := fileKeys.FilePointerUUID
	return filePointerUUID, nil
}

// Gets FilePointer of requested file
func getFilePointer(filename string, userdata User) (returnedFilePointer *FilePointer, err error) {

	var filePointer FilePointer
	filePointerptr := &filePointer

	if isUserOwner(filename, userdata) {

		// Get keys and UUID
		fileSymmetricKey, fileHMACKey, filePointerUUID, err := getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileOwned(filename, userdata)
		if err != nil {
			return nil, err
		}

		// Decrypt userFilePointer and store in &userFilePointer
		storedFilePointerMarshal, err := ReadFromDatastore(filePointerUUID, fileSymmetricKey, fileHMACKey[:lengthOfKey])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(storedFilePointerMarshal, filePointerptr)
		if err != nil {
			return nil, err
		}

		return filePointerptr, nil
	}
	if isFileSharedWithUser(filename, userdata) {

		// Get keys and UUID
		fileSymmetricKey, fileHMACKey, filePointerUUID, err := getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileShared(filename, userdata)
		if err != nil {
			return nil, err
		}

		// Decrypt userFilePointer and store in &userFilePointer
		storedFilePointerMarshal, err := ReadFromDatastore(filePointerUUID, fileSymmetricKey, fileHMACKey[:lengthOfKey])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(storedFilePointerMarshal, filePointerptr)
		if err != nil {
			return nil, err
		}

		return filePointerptr, nil

	}
	return nil, err
}

// Gets originalFileUUID from requested file
func setFilePointer(filename string, userdata User, filePointerUUID uuid.UUID, originalFileObjectUUID uuid.UUID, latestFileObjectUUID uuid.UUID, filePointerSymmetricKey []byte, filePointerHMACKey []byte) (err error) {

	filePointer, err := getFilePointer(filename, userdata)
	if err != nil {
		return err
	}
	filePointer.OriginalFileObjectUUID = originalFileObjectUUID
	filePointer.LatestFileObjectUUID = latestFileObjectUUID

	err = WriteToDatastore(filePointerUUID, filePointer, filePointerSymmetricKey, filePointerHMACKey)
	if err != nil {
		return err
	}
	return nil
}

// Gets originalFileObjectUUID of requested file
func getOriginalFileObjectUUID(filename string, userdata User) (returnedOriginalFileObjectUUID uuid.UUID, err error) {

	// Decrypt and get filePointer.originalFileObjectUUID
	filePointer, err := getFilePointer(filename, userdata)
	if err != nil {
		return uuid.Nil, err
	}
	originalFileObjectUUID := filePointer.OriginalFileObjectUUID
	return originalFileObjectUUID, nil
}

// Gets latestFileObjectUUID of requested file
func getLatestFileObjectUUID(filename string, userdata User) (returnedLatestFileObjectUUID uuid.UUID, err error) {

	// Decrypt and get filePointer.latestFileObjectUUID
	filePointer, err := getFilePointer(filename, userdata)
	if err != nil {
		return uuid.Nil, err
	}
	latestFileObjectUUID := filePointer.LatestFileObjectUUID
	return latestFileObjectUUID, nil
}

// Gets originalFileObject of requested file
func getOriginalFileObject(filename string, userdata User) (returnedOriginalFileObject *FileObject, err error) {

	var originalFileObject FileObject
	originalFileObjectptr := &originalFileObject

	originalFileObjectUUID, err := getOriginalFileObjectUUID(filename, userdata)
	if err != nil {
		return nil, err
	}

	if isUserOwner(filename, userdata) {

		// Get keys and UUID
		fileSymmetricKey, fileHMACKey, _, err := getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileOwned(filename, userdata)
		if err != nil {
			return nil, err
		}

		// Derive necessary keys
		_, fileObjectSymmetricKey, _ := DeriveFileSymmetricKey(fileSymmetricKey)
		_, fileObjectHMACKey, _ := DeriveFileHMACKey(fileHMACKey)

		// Decrypt userFilePointer and store in &userFilePointer
		storedOriginalFileObjectMarshal, err := ReadFromDatastore(originalFileObjectUUID, fileObjectSymmetricKey, fileObjectHMACKey[:lengthOfKey])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(storedOriginalFileObjectMarshal, originalFileObjectptr)
		if err != nil {
			return nil, err
		}

		return originalFileObjectptr, nil
	}
	if isFileSharedWithUser(filename, userdata) {

		// Get keys and UUID
		fileSymmetricKey, fileHMACKey, _, err := getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileShared(filename, userdata)
		if err != nil {
			return nil, err
		}

		// Derive necessary keys
		_, fileObjectSymmetricKey, _ := DeriveFileSymmetricKey(fileSymmetricKey)
		_, fileObjectHMACKey, _ := DeriveFileHMACKey(fileHMACKey)

		// Decrypt userFilePointer and store in &userFilePointer
		storedOriginalFileObjectMarshal, err := ReadFromDatastore(originalFileObjectUUID, fileObjectSymmetricKey, fileObjectHMACKey[:lengthOfKey])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(storedOriginalFileObjectMarshal, originalFileObjectptr)
		if err != nil {
			return nil, err
		}

		return originalFileObjectptr, nil
	}
	return nil, err
}

// Gets latestFileObject of requested file
func getLatestFileObject(filename string, userdata User) (returnedLatestFileObject *FileObject, err error) {

	var latestFileObject FileObject
	latestFileObjectptr := &latestFileObject

	latestFileObjectUUID, err := getLatestFileObjectUUID(filename, userdata)
	if err != nil {
		return nil, err
	}

	if isUserOwner(filename, userdata) {

		// Get keys and UUID
		fileSymmetricKey, fileHMACKey, _, err := getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileOwned(filename, userdata)
		if err != nil {
			return nil, err
		}

		// Derive necessary keys
		_, fileObjectSymmetricKey, _ := DeriveFileSymmetricKey(fileSymmetricKey)
		_, fileObjectHMACKey, _ := DeriveFileHMACKey(fileHMACKey)

		// Decrypt userFilePointer and store in &userFilePointer
		storedLatestFileObjectMarshal, err := ReadFromDatastore(latestFileObjectUUID, fileObjectSymmetricKey, fileObjectHMACKey[:lengthOfKey])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(storedLatestFileObjectMarshal, latestFileObjectptr)
		if err != nil {
			return nil, err
		}

		return latestFileObjectptr, nil
	}
	if isFileSharedWithUser(filename, userdata) {

		// Get keys and UUID
		fileSymmetricKey, fileHMACKey, _, err := getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileShared(filename, userdata)
		if err != nil {
			return nil, err
		}

		// Derive necessary keys
		_, fileObjectSymmetricKey, _ := DeriveFileSymmetricKey(fileSymmetricKey)
		_, fileObjectHMACKey, _ := DeriveFileHMACKey(fileHMACKey)

		// Decrypt userFilePointer and store in &userFilePointer
		storedLatestFileObjectMarshal, err := ReadFromDatastore(latestFileObjectUUID, fileObjectSymmetricKey, fileObjectHMACKey[:lengthOfKey])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(storedLatestFileObjectMarshal, latestFileObjectptr)
		if err != nil {
			return nil, err
		}

		return latestFileObjectptr, nil
	}
	return nil, err
}

// Gets fileObject from requested file
func setOriginalFileObject(filename string, userdata User, fileObjectUUID uuid.UUID, fileUUID uuid.UUID, nextFileObjectUUID uuid.UUID, fileObjectSymmetricKey []byte, fileObjectHMACKey []byte) (err error) {
	originalFileObject, err := getOriginalFileObject(filename, userdata)
	if err != nil {
		return err
	}
	originalFileObject.FileUUID = fileUUID
	originalFileObject.NextFileObjectUUID = nextFileObjectUUID

	err = WriteToDatastore(fileObjectUUID, originalFileObject, fileObjectSymmetricKey, fileObjectHMACKey)
	if err != nil {
		return err
	}
	return nil
}

// Gets fileObject from requested file
func setLatestFileObject(filename string, userdata User, fileObjectUUID uuid.UUID, fileUUID uuid.UUID, nextFileObjectUUID uuid.UUID, fileObjectSymmetricKey []byte, fileObjectHMACKey []byte) (err error) {
	latestFileObject, err := getLatestFileObject(filename, userdata)
	if err != nil {
		return err
	}
	latestFileObject.FileUUID = fileUUID
	latestFileObject.NextFileObjectUUID = nextFileObjectUUID

	err = WriteToDatastore(fileObjectUUID, latestFileObject, fileObjectSymmetricKey, fileObjectHMACKey)
	if err != nil {
		return err
	}
	return nil
}

func setNextFileObject(filename string, userdata User, appendedFileObjectUUID uuid.UUID, appendedFileUUID uuid.UUID, appendedNextFileObjectUUID uuid.UUID, fileObjectSymmetricKey []byte, fileObjectHMACKey []byte) (err error) {
	var fileObject FileObject

	fileObject.FileUUID = appendedFileUUID
	fileObject.NextFileObjectUUID = appendedNextFileObjectUUID

	// Write appended fileObject to Datastore
	err = WriteToDatastore(appendedFileObjectUUID, fileObject, fileObjectSymmetricKey, fileObjectHMACKey)
	if err != nil {
		return err
	}
	return nil
}

// Gets originalFileUUID from requested file
func getOriginalFileUUID(filename string, userdata User) (originalFileUUID uuid.UUID, err error) {
	originalFileObject, err := getOriginalFileObject(filename, userdata)
	if err != nil {
		return uuid.Nil, err
	}
	return originalFileObject.FileUUID, nil
}

// Gets latestFileUUID from requested file
func getLatestFileUUID(filename string, userdata User) (latestFileUUID uuid.UUID, err error) {
	latestFileObject, err := getLatestFileObject(filename, userdata)
	if err != nil {
		return uuid.Nil, err
	}
	return latestFileObject.FileUUID, nil
}

// Updates NextFileUUID in filePointer.latestFileUUID when appending files
func getNextFileObjectUUID(filename string, userdata User) (nextFileUUID uuid.UUID, err error) {
	latestFileObject, err := getLatestFileObject(filename, userdata)
	if err != nil {
		return uuid.Nil, err
	}
	return latestFileObject.NextFileObjectUUID, nil
}

func getFileKeysSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileOwned(filename string, userdata User) (returnedFileKeysSymmetricKey []byte, returnedFileKeysHMACKey []byte, returnedFileKeysUUID uuid.UUID, err error) {

	var fileOwnerInfo FileOwnerInfo
	fileOwnerInfoptr := &fileOwnerInfo

	// Derive symmetricKey and HMACKey to fileOwnerInfo of file
	fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey, err := DeriveFileOwnerInfoSymmetricKeyAndHMACKey(filename, userdata)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}

	// Get hashedFilenameUUID
	hashedFilenameUUID, err := getHashedFilenameUUID(filename)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}

	// Get fileOwnerInfo of requested file
	fileOwnerInfoUUID := userdata.FilesOwned[hashedFilenameUUID]
	storedFileOwnerInfoMarshal, err := ReadFromDatastore(fileOwnerInfoUUID, fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}
	err = json.Unmarshal(storedFileOwnerInfoMarshal, fileOwnerInfoptr)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}

	// Get keys to fileKeys from fileOwnerInfo
	fileKeysSymmetricKey := fileOwnerInfo.FileKeysSymmetricKey
	fileKeysHMACKey := fileOwnerInfo.FileKeysHMACKey
	fileKeysUUID := fileOwnerInfo.FileKeysUUID

	return fileKeysSymmetricKey, fileKeysHMACKey, fileKeysUUID, nil
}

func getFileKeysSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileShared(filename string, userdata User) (returnedFileKeysSymmetricKey []byte, returnedFileKeysHMACKey []byte, returnedFileKeysUUID uuid.UUID, err error) {

	// Get hashedFilenameUUID
	hashedFilenameUUID, err := getHashedFilenameUUID(filename)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}

	// Get fileOwnerInfo of requested file
	invitationKeysUUID := userdata.FilesShared[hashedFilenameUUID]

	_, invitation, err := VerifyDecryptAndReadInvitationFromDatastore(invitationKeysUUID, userdata)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}

	// Get keys to fileKeys from fileOwnerInfo
	fileKeysSymmetricKey := invitation.FileKeysSymmetricKey
	fileKeysHMACKey := invitation.FileKeysHMACKey
	fileKeysUUID := invitation.FileKeysUUID

	return fileKeysSymmetricKey, fileKeysHMACKey, fileKeysUUID, nil
}

func getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileOwned(filename string, userdata User) (returnedFileSymmetricKey []byte, returnedFileHMACKey []byte, returnedFilePointerUUID uuid.UUID, err error) {

	var fileKeys FileKeys
	fileKeysptr := &fileKeys

	// Get fileKeys keys and UUID
	fileKeysSymmetricKey, fileKeysHMACKey, fileKeysUUID, err := getFileKeysSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileOwned(filename, userdata)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}

	// Get fileKeys of requested file
	storedFileKeysMarshal, err := ReadFromDatastore(fileKeysUUID, fileKeysSymmetricKey, fileKeysHMACKey)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}
	err = json.Unmarshal(storedFileKeysMarshal, fileKeysptr)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}

	// Get keys to files from fileKeys
	fileSymmetricKey := fileKeys.FileSymmetricKey
	fileHMACKey := fileKeys.FileHMACKey
	filePointerUUID := fileKeys.FilePointerUUID

	return fileSymmetricKey, fileHMACKey, filePointerUUID, nil

}

func getFileSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileShared(filename string, userdata User) (returnedFileSymmetricKey []byte, returnedFileHMACKey []byte, returnedFilePointerUUID uuid.UUID, err error) {

	var fileKeys FileKeys
	fileKeysptr := &fileKeys

	// Get fileKeys keys and UUID
	fileKeysSymmetricKey, fileKeysHMACKey, fileKeysUUID, err := getFileKeysSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileShared(filename, userdata)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}

	// Get fileKeys of requested file
	storedFileKeysMarshal, err := ReadFromDatastore(fileKeysUUID, fileKeysSymmetricKey, fileKeysHMACKey)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}
	err = json.Unmarshal(storedFileKeysMarshal, fileKeysptr)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}

	// Get keys to files from fileKeys
	fileSymmetricKey := fileKeys.FileSymmetricKey
	fileHMACKey := fileKeys.FileHMACKey
	filePointerUUID := fileKeys.FilePointerUUID

	return fileSymmetricKey, fileHMACKey, filePointerUUID, nil

}

// Gets fileContent recursively
func getFileContentRecursively(filename string, originalFileObjectUUID uuid.UUID, latestFileObjectUUID uuid.UUID, fileObjectSymmetricKey []byte, fileObjectHMACKey []byte, fileSymmetricKey []byte, fileHMACKey []byte, userdata User) (returnedFileContent []byte, err error) {
	var fileObject FileObject
	var filedata File
	fileObjectptr := &fileObject
	filedataptr := &filedata

	storedFileObjectMarshal, err := ReadFromDatastore(originalFileObjectUUID, fileObjectSymmetricKey, fileObjectHMACKey[:lengthOfKey])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(storedFileObjectMarshal, fileObjectptr)
	if err != nil {
		return nil, err
	}

	fileUUID := fileObject.FileUUID
	nextFileObjectUUID := fileObject.NextFileObjectUUID

	storedFiledataMarshal, err := ReadFromDatastore(fileUUID, fileSymmetricKey, fileHMACKey[:lengthOfKey])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(storedFiledataMarshal, filedataptr)
	if err != nil {
		return nil, err
	}

	fileContent := filedata.Content

	_, ok := userlib.DatastoreGet(nextFileObjectUUID)

	// If ok is false there are no appends, so return filecontent
	if !ok {
		return fileContent, nil
	}

	if nextFileObjectUUID == latestFileObjectUUID {
		var latestFileObject FileObject
		var latestFiledata File
		latestFileObjectptr := &latestFileObject
		latestFiledataptr := &latestFiledata

		storedLatestFileObjectMarshal, err := ReadFromDatastore(latestFileObjectUUID, fileObjectSymmetricKey, fileObjectHMACKey[:lengthOfKey])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(storedLatestFileObjectMarshal, latestFileObjectptr)
		if err != nil {
			return nil, err
		}

		latestFileUUID := latestFileObject.FileUUID

		storedLatestFiledataMarshal, err := ReadFromDatastore(latestFileUUID, fileSymmetricKey, fileHMACKey[:lengthOfKey])
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(storedLatestFiledataMarshal, latestFiledataptr)
		if err != nil {
			return nil, err
		}
		//return fileContent, nil
		return append(fileContent, latestFiledata.Content...), nil
	} else {
		newFileContent, err := getFileContentRecursively(filename, nextFileObjectUUID, latestFileObjectUUID, fileObjectSymmetricKey, fileObjectHMACKey, fileSymmetricKey, fileHMACKey, userdata)
		if err != nil {
			return nil, err
		}
		return append(fileContent, newFileContent...), nil
	}
}

// Check if user has already accepted an invitation to the file
func checkIfUserAcceptedInvitationAlready(invitationKeysPtr uuid.UUID, userdata User) (err error) {
	for _, userInvitationUUID := range userdata.FilesShared {
		if userInvitationUUID == invitationKeysPtr {
			return errors.New("You have already accepted an invitation to this file.")
		}
	}
	return nil
}

// Decrypt and authenticate sendersUsername
func checkIfSenderIsAuthentic(invitationKeysPtr uuid.UUID, senderUsername string) (err error) {

	// Get VerificationKey of sender
	senderVerificationKeyID := senderUsername + "VerificationKey"
	senderVerificationKey, ok := userlib.KeystoreGet(senderVerificationKeyID)
	if !ok {
		return err
	}

	// Get storedSignedEncryptedInvitationMarshal from Datastore
	storedSignedEncryptedInvitationKeysMarshal, ok := userlib.DatastoreGet(invitationKeysPtr)
	if !ok {
		return err
	}

	// Separate encryptedInvitationMarshal and invitationSignature
	storedEncryptedInvitationKeysMarshal := storedSignedEncryptedInvitationKeysMarshal[:len(storedSignedEncryptedInvitationKeysMarshal)-lengthOfSHAKey]
	storedInvitationKeysSignature := storedSignedEncryptedInvitationKeysMarshal[len(storedSignedEncryptedInvitationKeysMarshal)-lengthOfSHAKey:]

	// Verify signature using senderVerificationKey
	err = userlib.DSVerify(senderVerificationKey, storedEncryptedInvitationKeysMarshal, storedInvitationKeysSignature)
	if err != nil {
		return err
	}

	return nil
}

// Check if fileKeys is shared with user. Return true if file is shared.
func checkIfFileKeysIsSharedWithUser(filename string, recipientUsername string, userdata User) (ok bool, err error) {

	// Get fileKeys from requested file
	fileKeys, err := getFileKeys(filename, userdata)
	if err != nil {
		return false, err
	}

	if fileKeys.OwnerUsername == recipientUsername {
		return true, nil
	}

	for storedSenderUsername, storedRecipients := range fileKeys.UsersSharedWith {
		for _, storedRecipientUsername := range storedRecipients {
			if storedSenderUsername == recipientUsername {
				return true, nil
			}
			if storedRecipientUsername == recipientUsername {
				return true, nil
			}
		}
	}
	return false, err
}

func addSharingToFileKeys(filename string, senderUsername string, recipientUsername string, userdata User) (err error) {

	var fileKeysSymmetricKey []byte
	var fileKeysHMACKey []byte

	fileKeysUUID, err := getFileKeysUUID(filename, userdata)
	if err != nil {
		return err
	}

	// Get fileKeys from requested file
	fileKeys, err := getFileKeys(filename, userdata)
	if err != nil {
		return err
	}

	// Throw error if file already is shared with recipientUsername
	ok, err := checkIfFileKeysIsSharedWithUser(filename, recipientUsername, userdata)
	if ok {
		return err
	}
	if err != nil {
		return err
	}

	// Add recipientUsername to fileKeys.UsersSharedWith[senderUsername]
	previousUsersSharedWith := fileKeys.UsersSharedWith[senderUsername]
	fileKeys.UsersSharedWith[senderUsername] = append(previousUsersSharedWith, recipientUsername)

	if isUserOwner(filename, userdata) {
		fileKeysSymmetricKey, fileKeysHMACKey, _, err = getFileKeysSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileOwned(filename, userdata)
		if err != nil {
			return err
		}
	}
	if isFileSharedWithUser(filename, userdata) {
		fileKeysSymmetricKey, fileKeysHMACKey, _, err = getFileKeysSymmetricKeyFileHMACKeyAndFilePointerUUIDFromFileShared(filename, userdata)
		if err != nil {
			return err
		}
	}

	// Write updated fileKeys to Datastore
	err = WriteToDatastore(fileKeysUUID, fileKeys, fileKeysSymmetricKey, fileKeysHMACKey)
	if err != nil {
		return err
	}

	return nil
}

func removeAccess(filename string, recipientUsername string, storedFileKeysSymmetricKey []byte, storedFileKeysHMACKey []byte, userdata User) (err error) {

	var updatedUsersSharedWith map[string][]string

	// Get fileKeysUUID from requested file
	fileKeysUUID, err := getFileKeysUUID(filename, userdata)
	if err != nil {
		return err
	}

	// Get fileKeys from requested file
	fileKeys, err := getFileKeys(filename, userdata)
	if err != nil {
		return err
	}

	// Remove access of recipients and users they have shared with
	for storedSenderUsername, storedRecipients := range fileKeys.UsersSharedWith {
		for _, storedRecipientUsername := range storedRecipients {
			if storedSenderUsername != recipientUsername {
				if storedRecipientUsername != recipientUsername {
					updatedUsersSharedWith[storedSenderUsername] = append(updatedUsersSharedWith[storedSenderUsername], storedRecipientUsername)
				}
			}
		}
	}

	// Update fileKeys.UsersSharedWith
	fileKeys.UsersSharedWith = updatedUsersSharedWith

	// Write updated fileKeys to Datastore
	err = WriteToDatastore(fileKeysUUID, fileKeys, storedFileKeysSymmetricKey, storedFileKeysHMACKey)
	if err != nil {
		return err
	}

	return nil
}

// Derives unique invitationUUID for user per file
func deriveInvitationKeysUUID(recipientUsername string, invitationSalt string) (derivedInvitationKeysUUID uuid.UUID, err error) {

	// Concatenate recipientUsername with invitationSalt
	hashedInvitationKeys := userlib.Hash([]byte(recipientUsername + invitationSalt))
	invitationKeysUUID, err := uuid.FromBytes(hashedInvitationKeys[:lengthOfKey])
	if err != nil {
		return uuid.Nil, err
	}

	return invitationKeysUUID, nil
}

// Updates FilePointer and all Files in the file
func updateFiles(filename string, updatedFilePointerUUID uuid.UUID, updatedFileSymmetricKey []byte, updatedFileHMACKey []byte, storedFileSymmetricKey []byte, storedFileHMACKey []byte, userdata User) (err error) {

	var updatedFileObject FileObject
	var updatedFile File
	updatedOriginalFileObjectUUID := uuid.New()
	updatedOriginalFileUUID := uuid.New()
	updatedNextFileObjectUUID := uuid.New()

	// Hash storedSymmetricKey to read from Datastore
	oldFilePointerSymmetricKey := storedFileSymmetricKey
	oldFileObjectSymmetricKey := userlib.Hash(oldFilePointerSymmetricKey)
	oldFileSymmetricKey := userlib.Hash(oldFileObjectSymmetricKey)

	// Hash storedHMACKey to read from Datastore
	oldFilePointerHMACKey := storedFileHMACKey
	oldFileObjectHMACKey := userlib.Hash(oldFilePointerHMACKey)
	oldFileHMACKey := userlib.Hash(oldFileObjectHMACKey)

	// Get originalFileUUID and latestFileUUID before filePointer is updated
	filePointer, err := getFilePointer(filename, userdata)
	if err != nil {
		return err
	}
	originalFileObjectUUID, err := getOriginalFileObjectUUID(filename, userdata)
	if err != nil {
		return err
	}
	latestFileObjectUUID, err := getLatestFileObjectUUID(filename, userdata)
	if err != nil {
		return err
	}

	// Get fileContent from files recursively
	fileContent, err := getFileContentRecursively(filename, originalFileObjectUUID, latestFileObjectUUID, oldFileObjectSymmetricKey, oldFileObjectHMACKey, oldFileSymmetricKey, oldFileHMACKey, userdata)
	if err != nil {
		return err
	}

	// Add fileContent to updatedFile
	updatedFile.Content = fileContent

	// Hash updatedSymmetricKey to reuse for FilePointer, FileObject and File
	filePointerSymmetricKey := updatedFileSymmetricKey
	fileObjectSymmetricKey := userlib.Hash(filePointerSymmetricKey)
	fileSymmetricKey := userlib.Hash(fileObjectSymmetricKey)

	// Hash updatedHMACKey to reuse for FilePointer, FileObject and File
	filePointerHMACKey := updatedFileHMACKey
	fileObjectHMACKey := userlib.Hash(filePointerHMACKey)
	fileHMACKey := userlib.Hash(fileObjectHMACKey)

	// Encrypt and store file in a new UUID in Datastore
	err = WriteToDatastore(updatedOriginalFileUUID, updatedFile, fileSymmetricKey, fileHMACKey)
	if err != nil {
		return err
	}

	// Add updatedOriginalFileUUID and updatedNextFileUUID to updatedFileObject
	updatedFileObject.FileUUID = updatedOriginalFileUUID
	updatedFileObject.NextFileObjectUUID = updatedNextFileObjectUUID

	// Encrypt and store file in a new UUID in Datastore
	err = WriteToDatastore(updatedOriginalFileObjectUUID, updatedFileObject, fileObjectSymmetricKey, fileObjectHMACKey)
	if err != nil {
		return err
	}

	// Update FilePointer of File
	filePointer.OriginalFileObjectUUID = updatedOriginalFileObjectUUID
	filePointer.LatestFileObjectUUID = updatedOriginalFileObjectUUID

	// Encrypt and store filePointer in a new UUID in Datastore
	err = WriteToDatastore(updatedFilePointerUUID, filePointer, filePointerSymmetricKey, filePointerHMACKey)
	if err != nil {
		return err
	}

	return nil
}

// Updates FileKeys
func UpdateFileKeys(filename string, updatedFilePointerUUID uuid.UUID, updatedFileKeysUUID uuid.UUID, storedFileKeysUUID uuid.UUID, updatedFileSymmetricKey []byte, updatedFileHMACKey []byte, updatedFileKeysSymmetricKey []byte, updatedFileKeysHMACKey []byte, storedFileKeysSymmetricKey []byte, storedFileKeysHMACKey []byte, userdata User) (err error) {

	var updatedFileKeys FileKeys
	updatedFileKeysptr := &updatedFileKeys

	// Get fileKeys
	storedUpdatedFileKeysMarshal, err := ReadFromDatastore(storedFileKeysUUID, storedFileKeysSymmetricKey, storedFileKeysHMACKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(storedUpdatedFileKeysMarshal, updatedFileKeysptr)
	if err != nil {
		return err
	}

	// Change encryption keys
	updatedFileKeys.FileSymmetricKey = updatedFileSymmetricKey
	updatedFileKeys.FileHMACKey = updatedFileHMACKey
	updatedFileKeys.FilePointerUUID = updatedFilePointerUUID

	// Encrypt and store in a new UUID in Datastore
	err = WriteToDatastore(updatedFileKeysUUID, updatedFileKeys, updatedFileKeysSymmetricKey, updatedFileKeysHMACKey)
	if err != nil {
		return err
	}

	return nil
}

// Updates keys and UUID of an invitation to a file
func updateInvitation(filename string, updatedRecipientUsername string, invitationSalt string, fileOwnerInfoUUID uuid.UUID, updatedFileKeysUUID uuid.UUID, updatedFileKeysSymmetricKey []byte, updatedFileKeysHMACKey []byte, sender User) (err error) {

	var updatedInvitationKeys InvitationKeys
	var updatedInvitation Invitation

	// Get invtitationUUID of requested file
	invitationKeysUUID, err := deriveInvitationKeysUUID(updatedRecipientUsername, invitationSalt)
	if err != nil {
		return err
	}
	invitationUUID := uuid.New()

	// Update keys and UUID
	updatedInvitationKeys.SK = userlib.RandomBytes(lengthOfKey)
	updatedInvitationKeys.HK = userlib.RandomBytes(lengthOfKey)
	updatedInvitationKeys.ID = invitationUUID
	updatedInvitation.FileKeysSymmetricKey = updatedFileKeysSymmetricKey
	updatedInvitation.FileKeysHMACKey = updatedFileKeysHMACKey
	updatedInvitation.FileKeysUUID = updatedFileKeysUUID
	updatedInvitation.InvitationSalt = invitationSalt

	// Sign, encrypt and write invitationKeys to Datastore
	err = SignEncryptAndWriteInvitationKeysToDatastore(invitationKeysUUID, updatedInvitationKeys, updatedRecipientUsername, sender)
	if err != nil {
		return err
	}

	// Encrypt and write invitation to Datastore
	err = WriteToDatastore(invitationUUID, updatedInvitation, updatedInvitationKeys.SK, updatedInvitationKeys.HK)
	if err != nil {
		return err
	}

	return nil
}

// Updates keys and UUID of invitations to a file
func updateInvitations(filename string, fileOwnerInfoUUID uuid.UUID, updatedFileKeysUUID uuid.UUID, updatedFileKeysSymmetricKey []byte, updatedFileKeysHMACKey []byte, userdata User) (err error) {

	var fileOwnerInfo FileOwnerInfo
	fileOwnerInfoptr := &fileOwnerInfo

	// Get symmetricKey and HMACKey to fileOwnerInfo of file
	fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey, err := DeriveFileOwnerInfoSymmetricKeyAndHMACKey(filename, userdata)
	if err != nil {
		return err
	}

	// Get fileOwnerInfo of requested filed
	storedFileOwnerInfoMarshal, err := ReadFromDatastore(fileOwnerInfoUUID, fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(storedFileOwnerInfoMarshal, fileOwnerInfoptr)
	if err != nil {
		return err
	}

	// Get invitationSalt from fileOwnerInfo
	invitationSalt := fileOwnerInfo.InvitationSalt

	// Get newFileKeys from requested file
	updatedFileKeys, err := getFileKeys(filename, userdata)
	if err != nil {
		return err
	}

	// Get usersSharedWith from updatedFileKeys
	usersSharedWith := updatedFileKeys.UsersSharedWith

	// Update keys and UUID of all invitations
	for _, updatedRecipients := range usersSharedWith {
		for _, updatedRecipientUsername := range updatedRecipients {
			err = updateInvitation(filename, updatedRecipientUsername, invitationSalt, fileOwnerInfoUUID, updatedFileKeysUUID, updatedFileKeysSymmetricKey, updatedFileKeysHMACKey, userdata)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func updateFileOwnerInfo(filename string, fileOwnerInfoUUID uuid.UUID, updatedFileKeysUUID uuid.UUID, updatedFileKeysSymmetricKey []byte, updatedFileKeysHMACKey []byte, userdata User) (err error) {

	var updatedFileOwnerInfo FileOwnerInfo
	updatedFileOwnerInfoptr := &updatedFileOwnerInfo

	// Get symmetricKey and HMACKey to fileOwnerInfo of file
	fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey, err := DeriveFileOwnerInfoSymmetricKeyAndHMACKey(filename, userdata)
	if err != nil {
		return err
	}

	// Get fileOwnerInfo from Datastore
	storedFileOwnerInfoMarshal, err := ReadFromDatastore(fileOwnerInfoUUID, fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(storedFileOwnerInfoMarshal, updatedFileOwnerInfoptr)
	if err != nil {
		return err
	}

	// Update keys and UUID
	updatedFileOwnerInfo.FileKeysSymmetricKey = updatedFileKeysSymmetricKey
	updatedFileOwnerInfo.FileKeysHMACKey = updatedFileKeysHMACKey
	updatedFileOwnerInfo.FileKeysUUID = updatedFileKeysUUID

	// Encrypt and store in the same UUID in Datastore
	// Owner stores using their symmetricKey and HMACKey
	err = WriteToDatastore(fileOwnerInfoUUID, updatedFileOwnerInfo, fileOwnerInfoSymmetricKey, fileOwnerInfoHMACKey)
	if err != nil {
		return err
	}

	return nil
}

func UpdateUser(username string, hashedPassword []byte) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Throw error if user doesn't exist
	if !checkIfUserExists(username) {
		return nil, err
	}

	// Derive symmetricKey
	symmetricKey := userlib.Argon2Key([]byte(hashedPassword), []byte(username), 16)

	// Derive HMACKey
	HMACKey, err := userlib.HashKDF(symmetricKey, []byte("HMAC of userdata"))
	if err != nil {
		return nil, err
	}

	// Get UUID of userdata
	hashedUsername := userlib.Hash([]byte(username))
	usernameUUID, err := uuid.FromBytes(hashedUsername[:lengthOfKey])
	if err != nil {
		return nil, err
	}

	// Get userdata from Datastore
	storedUserdataMarshal, err := ReadFromDatastore(usernameUUID, symmetricKey, HMACKey)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(storedUserdataMarshal, userdataptr)
	if err != nil {
		return nil, err
	}

	// Set keys
	userdata.Username = username
	userdata.HashedPassword = hashedPassword
	userdata.SymmetricKey = symmetricKey
	userdata.HMACKey = HMACKey

	return userdataptr, nil
}

func WriteUpdatedUserToDatastore(userdata User) (err error) {

	usernameUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:lengthOfKey])
	if err != nil {
		return err
	}

	err = WriteToDatastore(usernameUUID, userdata, userdata.SymmetricKey, userdata.HMACKey)
	if err != nil {
		return err
	}
	return nil
}

func deleteOldFileKeys(storedFileKeysUUID uuid.UUID) {
	userlib.DatastoreDelete(storedFileKeysUUID)
}

func deleteOldFiles(filename string, storedFilePointerUUID uuid.UUID, storedOriginalFileObjectUUID uuid.UUID, storedLatestFileObjectUUID uuid.UUID, storedFilePointerSymmetricKey []byte, storedFilePointerHMACKey []byte, userdata User) (err error) {

	// Derive fileObjectSymmetricKey and fileObjectHMACKey
	storedFileObjectSymmetricKey := userlib.Hash(storedFilePointerSymmetricKey)
	storedFileObjectHMACKey := userlib.Hash(storedFilePointerHMACKey)

	// Delete FileObjects and Files recursively
	deleteFileObjectsAndFilesRecursively(storedOriginalFileObjectUUID, storedLatestFileObjectUUID, storedFileObjectSymmetricKey, storedFileObjectHMACKey)
	if err != nil {
		return err
	}

	// Delete FilePointer
	userlib.DatastoreDelete(storedFilePointerUUID)

	return nil
}

func deleteFileObjectsAndFilesRecursively(storedOriginalFileObjectUUID uuid.UUID, storedLatestFileObjectUUID uuid.UUID, storedFileObjectSymmetricKey []byte, storedFileObjectHMACKey []byte) (err error) {

	var storedFileObject FileObject
	storedFileObjectptr := &storedFileObject

	// Get fileObject from Datastore
	storedFileObjectMarshal, err := ReadFromDatastore(storedOriginalFileObjectUUID, storedFileObjectSymmetricKey, storedFileObjectHMACKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(storedFileObjectMarshal, storedFileObjectptr)
	if err != nil {
		return err
	}

	// Get fileUUID and nextFileObjectUUID
	storedFileUUID := storedFileObject.FileUUID
	storedNextFileObjectUUID := storedFileObject.NextFileObjectUUID

	// Delete fileUUID and nextFileObjectUUID recursively
	if storedNextFileObjectUUID == storedLatestFileObjectUUID {
		userlib.DatastoreDelete(storedFileUUID)
		return nil
	} else {
		deleteFileObjectsAndFilesRecursively(storedNextFileObjectUUID, storedLatestFileObjectUUID, storedFileObjectSymmetricKey, storedFileObjectHMACKey)
		userlib.DatastoreDelete(storedNextFileObjectUUID)
		userlib.DatastoreDelete(storedFileUUID)
		return nil
	}
}
