package com.ixayda.iam;

import java.util.stream.Collectors;

import org.springframework.jdbc.core.simple.JdbcClient;

/** Copies current fixtures using the destination version's explicit column contract. */
public final class PostgreSqlMigrationTestSupport {

	private PostgreSqlMigrationTestSupport() { }

	public static void copyRows(JdbcClient target, String table) {
		if (!table.matches("iam_[a-z_]+")) { throw new IllegalArgumentException("Invalid fixture table"); }
		String columns = target.sql("""
				SELECT column_name FROM information_schema.columns
				WHERE table_schema = current_schema() AND table_name = :table ORDER BY ordinal_position
				""").param("table", table).query(String.class).list().stream()
				.map(column -> "\"" + column.replace("\"", "\"\"") + "\"").collect(Collectors.joining(", "));
		if (columns.isEmpty()) { throw new IllegalStateException("Fixture destination table is missing"); }
		target.sql("INSERT INTO " + table + " (" + columns + ") SELECT " + columns + " FROM public." + table).update();
	}

}
