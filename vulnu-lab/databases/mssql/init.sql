CREATE DATABASE UniversityDB;
GO
USE UniversityDB;
CREATE TABLE Students (Id INT PRIMARY KEY, Name NVARCHAR(100), Grade INT);
INSERT INTO Students (Id, Name, Grade) VALUES (102, 'Alice', 85), (103, 'Bob', 90);
GO