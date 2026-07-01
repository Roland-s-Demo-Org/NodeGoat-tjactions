const assert = require("assert");
const should = require("should");

describe("UserDAO - NoSQL Injection Protection", function() {
    "use strict";

    let db;
    let UserDAO;
    let userDAO;
    let usersCol;

    before(function(done) {
        // Setup mock database and collection
        const mongodb = require("mongodb");
        const MongoClient = mongodb.MongoClient;
        const config = require("../../config/config");

        MongoClient.connect(config.db, function(err, database) {
            if (err) {
                console.error("Failed to connect to database:", err);
                return done(err);
            }
            db = database;
            UserDAO = require("../../app/data/user-dao").UserDAO;
            userDAO = new UserDAO(db);
            usersCol = db.collection("users");
            done();
        });
    });

    after(function(done) {
        if (db) {
            db.close(done);
        } else {
            done();
        }
    });

    beforeEach(function(done) {
        // Clear users collection and insert test data
        usersCol.deleteMany({}, function(err) {
            if (err) return done(err);

            // Insert test users
            usersCol.insertMany([
                {
                    _id: 1,
                    userName: "testuser",
                    firstName: "Test",
                    lastName: "User",
                    password: "password123",
                    email: "test@example.com"
                },
                {
                    _id: 2,
                    userName: "admin",
                    firstName: "Admin",
                    lastName: "User",
                    password: "admin123",
                    email: "admin@example.com"
                }
            ], done);
        });
    });

    describe("validateLogin - NoSQL Injection Prevention", function() {

        it("should successfully login with valid credentials", function(done) {
            userDAO.validateLogin("testuser", "password123", function(err, user) {
                should.not.exist(err);
                should.exist(user);
                user.userName.should.equal("testuser");
                user.firstName.should.equal("Test");
                done();
            });
        });

        it("should fail login with invalid password", function(done) {
            userDAO.validateLogin("testuser", "wrongpassword", function(err, user) {
                should.exist(err);
                err.invalidPassword.should.be.true();
                should.not.exist(user);
                done();
            });
        });

        it("should fail login with non-existent user", function(done) {
            userDAO.validateLogin("nonexistent", "password123", function(err, user) {
                should.exist(err);
                err.noSuchUser.should.be.true();
                should.not.exist(user);
                done();
            });
        });

        it("should prevent NoSQL injection with $ne operator", function(done) {
            // Attempt to bypass authentication using {$ne: null}
            // This should fail because the fix wraps userName with {$eq: userName}
            const maliciousInput = {$ne: null};
            
            userDAO.validateLogin(maliciousInput, "password123", function(err, user) {
                // Should not find any user because the query becomes:
                // {userName: {$eq: {$ne: null}}} which won't match any document
                should.exist(err);
                err.noSuchUser.should.be.true();
                should.not.exist(user);
                done();
            });
        });

        it("should prevent NoSQL injection with $gt operator", function(done) {
            // Attempt to bypass authentication using {$gt: ""}
            const maliciousInput = {$gt: ""};
            
            userDAO.validateLogin(maliciousInput, "password123", function(err, user) {
                should.exist(err);
                err.noSuchUser.should.be.true();
                should.not.exist(user);
                done();
            });
        });

        it("should prevent NoSQL injection with $regex operator", function(done) {
            // Attempt to bypass authentication using regex
            const maliciousInput = {$regex: ".*"};
            
            userDAO.validateLogin(maliciousInput, "password123", function(err, user) {
                should.exist(err);
                err.noSuchUser.should.be.true();
                should.not.exist(user);
                done();
            });
        });

        it("should prevent NoSQL injection with $where operator", function(done) {
            // Attempt to inject JavaScript code
            const maliciousInput = {$where: "this.userName == 'admin'"};
            
            userDAO.validateLogin(maliciousInput, "password123", function(err, user) {
                should.exist(err);
                err.noSuchUser.should.be.true();
                should.not.exist(user);
                done();
            });
        });

        it("should handle object input as literal value", function(done) {
            // Even if an object is passed, it should be treated as a literal value
            // and not match any user (unless a user literally has an object as userName)
            const objectInput = {someKey: "someValue"};
            
            userDAO.validateLogin(objectInput, "password123", function(err, user) {
                should.exist(err);
                err.noSuchUser.should.be.true();
                should.not.exist(user);
                done();
            });
        });

        it("should handle special characters in username correctly", function(done) {
            // First, insert a user with special characters
            usersCol.insertOne({
                _id: 99,
                userName: "user$special",
                firstName: "Special",
                lastName: "User",
                password: "pass123"
            }, function(err) {
                if (err) return done(err);

                userDAO.validateLogin("user$special", "pass123", function(err, user) {
                    should.not.exist(err);
                    should.exist(user);
                    user.userName.should.equal("user$special");
                    done();
                });
            });
        });

        it("should only match exact username with $eq operator", function(done) {
            // Verify that $eq ensures exact matching
            userDAO.validateLogin("test", "password123", function(err, user) {
                // Should not match "testuser" because we're looking for exact "test"
                should.exist(err);
                err.noSuchUser.should.be.true();
                should.not.exist(user);
                done();
            });
        });

        it("should handle empty string username", function(done) {
            userDAO.validateLogin("", "password123", function(err, user) {
                should.exist(err);
                err.noSuchUser.should.be.true();
                should.not.exist(user);
                done();
            });
        });

        it("should handle null username", function(done) {
            userDAO.validateLogin(null, "password123", function(err, user) {
                should.exist(err);
                err.noSuchUser.should.be.true();
                should.not.exist(user);
                done();
            });
        });

        it("should handle undefined username", function(done) {
            userDAO.validateLogin(undefined, "password123", function(err, user) {
                should.exist(err);
                err.noSuchUser.should.be.true();
                should.not.exist(user);
                done();
            });
        });
    });

    describe("Query structure verification", function() {
        
        it("should construct query with $eq operator for userName", function(done) {
            // This test verifies the fix is in place by checking the query structure
            // We'll spy on the findOne call to verify the query structure
            const originalFindOne = usersCol.findOne;
            let capturedQuery = null;

            usersCol.findOne = function(query, callback) {
                capturedQuery = query;
                return originalFindOne.call(this, query, callback);
            };

            userDAO.validateLogin("testuser", "password123", function(err, user) {
                // Restore original method
                usersCol.findOne = originalFindOne;

                should.not.exist(err);
                should.exist(capturedQuery);
                
                // Verify the query structure includes $eq
                capturedQuery.should.have.property("userName");
                capturedQuery.userName.should.be.an.Object();
                capturedQuery.userName.should.have.property("$eq");
                capturedQuery.userName.$eq.should.equal("testuser");
                
                done();
            });
        });
    });
});
