using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace backend.Migrations
{
    /// <inheritdoc />
    public partial class UpdateAuthChallengeAndSessionIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "LastResentAt",
                table: "user_auth_challenges",
                type: "timestamptz",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ResendCount",
                table: "user_auth_challenges",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateIndex(
                name: "IX_sessions_SessionTokenHash",
                table: "sessions",
                column: "SessionTokenHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_sessions_SessionTokenHash",
                table: "sessions");

            migrationBuilder.DropColumn(
                name: "LastResentAt",
                table: "user_auth_challenges");

            migrationBuilder.DropColumn(
                name: "ResendCount",
                table: "user_auth_challenges");
        }
    }
}
