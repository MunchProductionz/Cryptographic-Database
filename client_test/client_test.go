package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	"strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

const contentAlice = "This is Alice's file"
const contentBob = "This is Bob's file"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var bobLaptop *client.User
	var bobDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	fooFile := "foo.txt"
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	// 3.1: Usernames and Passwords
	Describe("Custom tests 3.1", func() {

		Specify("Custom test (3.1.1.a): Testing that usernames are unique.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob with the same username as Alice.")
			bob, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom test (3.1.1.b): Testing that usernames are case sensitive.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice with capital A.")
			bob, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Custom test (3.1.1.c): Testing that usernames cannot be empty.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob with empty username.")
			bob, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom test (3.1.2.a): Testing that users can have the same password.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob with empty username.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Custom test (3.1.2.c): Testing that passwords can be empty.", func() {
			userlib.DebugMsg("Initializing user Alice with empty password.")
			alice, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob with default password.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Custom test: Testing login with wrong password.", func() {
			userlib.DebugMsg("Initializing user Alice with empty password.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", "wrongPassword")
			Expect(err).ToNot(BeNil())
		})
	})

	// 3.2: User Sessions
	Describe("Custom tests 3.2", func() {

		Specify("Custom test (3.2.2): Testing that a single user can have multiple sessions.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceDesktop")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores a file on her laptop.")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice grabs the file on her desktop.")
			aliceData, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(aliceData).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice appends to the file on her desktop.")
			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice grabs the updated file on her laptop.")
			aliceData, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(aliceData).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("Custom test (3.2.2): Testing that user can accept an invitation on one device and load it on another.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceDesktop")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob stores a file.")
			err = bob.StoreFile(bobFile, []byte(contentBob))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob sends an invitation to Alice.")
			inv, err := bob.CreateInvitation(bobFile, "alice")
			Expect(err).To(BeNil())
			Expect(inv).ToNot(BeNil())

			userlib.DebugMsg("Alice accepts the invitation on her laptop.")
			aliceLaptop.AcceptInvitation("bob", inv, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loads the file on her desktop.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentBob)))
		})

	})

	// 3.3: Cryptography and Keys
	Describe("Custom tests 3.3", func() {

	})

	// 3.4: No Persistent Local State
	Describe("Custom tests 3.4", func() {

	})

	// 3.5: Files
	Describe("Custom tests 3.5", func() {

		// Expand?
		Specify("Custom test (3.5.1): Testing that Eve cannot read Alice's file.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Eve.")
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentAlice)
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve tries to read it.")
			data, _ := eve.LoadFile(aliceFile)
			Expect(data).ToNot(Equal([]byte(contentAlice)))
		})

		// Not needed (?)
		Specify("Custom test (3.5.3): Testing the integrity of file names.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Eve.")
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentAlice)
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			lengthOfFileAlice := len([]byte(data))

			userlib.DebugMsg("Eve tries to retrieve the length of the file.")
			data, _ = eve.LoadFile(aliceFile)
			lengthOfFileEve := len([]byte(data))
			Expect(lengthOfFileAlice).ToNot(Equal(lengthOfFileEve))
		})

		Specify("Custom test (3.5.6): Testing that file names can be empty.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentAlice)
			err = alice.StoreFile("", []byte(contentAlice))
			Expect(err).To(BeNil())
		})

		Specify("Custom test (3.5.7): Testing that files can have the same name across several users.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentAlice)
			err = alice.StoreFile(fooFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentBob)
			err = bob.StoreFile(fooFile, []byte(contentBob))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			aliceData, err := alice.LoadFile(fooFile)
			Expect(err).To(BeNil())
			bobData, err := bob.LoadFile(fooFile)
			Expect(aliceData).ToNot(Equal(bobData))
		})
	})

	// 3.6: Sharing and Revocation
	Describe("Custom tests 3.6", func() {

		Specify("Custom test (3.6.1): Enforce authorization for all files.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates a file.")
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice sees expected file data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentAlice)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentAlice)))

			userlib.DebugMsg("Checking that Charles does not see the expected file data.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom test (3.6.2): Invitees have the desired authorizations.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates a file.")
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentAlice)))

			userlib.DebugMsg("Checking that Bob can overwrite file data.")
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can append to file data.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can invite Charles.")
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite from Bob")
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())
		})

		Specify("Custom test (3.6.3): All authorized users have same file content.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Doris.")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates a file.")
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appends to file data.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creates invite for Charles.")
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite from Bob")
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles appends to file data.")
			err = bob.AppendToFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file for Alice...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Loading file for Bob...")
			data2, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Loading file for Charles...")
			data3, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data3).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Alice creates invite for Doris.")
			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris accepting invite from Alice")
			err = charles.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Doris can overwrite file data.")
			err = doris.StoreFile(dorisFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file for Alice...")
			data4, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data4).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Loading file for Bob...")
			data5, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data5).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Loading file for Charles...")
			data6, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data6).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Loading file for Doris...")
			data7, err := doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data7).To(Equal([]byte(contentOne)))
		})

		Specify("Custom test (3.6.9): Revoke down the tree.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Doris.")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates a file.")
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Eve.")
			invite, err = alice.CreateInvitation(aliceFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve accepting invite from Alice")
			err = eve.AcceptInvitation("alice", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creates invite for Charles.")
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite from Bob")
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creates invite for Doris.")
			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris accepting invite from Bob")
			err = charles.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob, Charles and Doris lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = doris.AppendToFile(dorisFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot overwrite the file.")
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.StoreFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = doris.StoreFile(dorisFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Eve still has access to the file.")
			data, err := eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentAlice)))
		})
	})

	// 3.7: Efficiency
	Describe("Custom tests 3.7", func() {

		Specify("Custom Test (3.7.1): Testing efficient append.", func() {
			measureBandwidth := func(probe func()) (bandwidth int) {
				before := userlib.DatastoreGetBandwidth()
				probe()
				after := userlib.DatastoreGetBandwidth()
				return after - before
			}

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates a file.")
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			bw1 := measureBandwidth(func() {
				err := alice.AppendToFile(aliceFile, []byte("A"))
				Expect(err).To(BeNil())
			})

			bw2 := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(strings.Repeat("A", 10000)))
				Expect(err).To(BeNil())
			})

			bw3 := measureBandwidth(func() {
				err := alice.AppendToFile(aliceFile, []byte("A"))
				Expect(err).To(BeNil())
			})

			bw4 := measureBandwidth(func() {
				err := alice.AppendToFile(aliceFile, []byte("A"))
				Expect(err).To(BeNil())
			})

			Expect(bw3).ToNot(BeNil())

			Expect(bw1*2 > bw4)
			Expect(bw4*2 > bw1)
			Expect(bw1*2 > bw3)
			Expect(bw3*2 > bw1)
			Expect(bw3*2 > bw4)
			Expect(bw4*2 > bw3)
			Expect(bw2 > bw4)
			Expect(bw2 > bw1)
			Expect(bw2 > bw3)

		})
	})

	// Other tests
	Describe("Custom tests", func() {

		Specify("Custom test: Try stuff out on file you don't have access to.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates a file.")
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob tries to revoke Alice's access to the file.")
			err = bob.RevokeAccess(aliceFile, "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to invite Charles to the file.")
			invite, err := bob.CreateInvitation(aliceFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles cannot accept invitation from Bob")
			err = charles.AcceptInvitation("bob", invite, aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to append to the file.")
			err = bob.AppendToFile(aliceFile, []byte(contentBob))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom test: Testing that file content can be empty.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates a file.")
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())
		})

		Specify("Custom test: Testing that invites cancel.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bobDesktop, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Bob - bobLaptop")
			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates a file.")
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Bob.")
			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates another invite for Bob.")
			invite2, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite1 from Alice")
			err = bobDesktop.AcceptInvitation("alice", invite1, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob cannot accept invite2 from Alice once he's revoked (desktop).")
			err = bobDesktop.AcceptInvitation("alice", invite2, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob cannot accept invite2 from Alice once he's revoked (laptop).")
			err = bobLaptop.AcceptInvitation("alice", invite2, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom test: Cannot do stuff on files that don't exist.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Try to load file.")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Try to append file data: %s", contentAlice)
			err = alice.AppendToFile(aliceFile, []byte(contentAlice))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice tries to invite Bob to the file.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob cannot accept invitation from Alice")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom test: Cannot accept invitation not for you.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file")
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice tries to invite Bob to the file.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles cannot accept invite")
			err = charles.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepts invitation from Alice")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles cannot accept invite")
			err = charles.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom test: Cannot accept invitation not for you.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file")
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice tries to invite Bob to the file.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles cannot accept invite")
			err = charles.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepts invitation from Alice")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles cannot accept invite")
			err = charles.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom test: Accept invitation after appending.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice tries to invite Bob to the file.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invitation from Alice")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file, should see new content")
			data, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("Custom test: Accept invitation after overwriting.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice tries to invite Bob to the file.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file")
			err = alice.StoreFile(aliceFile, []byte(contentAlice))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invitation from Alice")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file, should see new content")
			data, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentAlice)))
		})
	})
})
