package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// Package mirrors one row of packages. Quota applied onto a key when purchased.
type Package struct {
	ID           string
	Name         string
	Description  string
	QuotaKind    string
	QuotaScope   string
	QuotaAmount  int64
	PlanType     string
	WindowHours  int64
	DurationDays int64
	PriceCredit  int64
	ModelsJSON   string
	RPM          int
	Visible      bool
	CreatedAt    int64
}

type PackagesRepo struct{ db *DB }

func (d *DB) Packages() *PackagesRepo { return &PackagesRepo{db: d} }

const packageColumns = `id, name, COALESCE(description,''), quota_kind, quota_scope,
	quota_amount, plan_type, COALESCE(window_hours,0), duration_days, price_credit, COALESCE(allowed_models,'[]'), rpm,
	visible, created_at`

func scanPackage(row interface{ Scan(...any) error }) (Package, error) {
	var p Package
	var visible int
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.QuotaKind, &p.QuotaScope,
		&p.QuotaAmount, &p.PlanType, &p.WindowHours, &p.DurationDays, &p.PriceCredit, &p.ModelsJSON, &p.RPM,
		&visible, &p.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return Package{}, ErrNotFound
		}
		return Package{}, fmt.Errorf("scan package: %w", err)
	}
	p.Visible = visible != 0
	return p, nil
}

func (r *PackagesRepo) ByID(id string) (Package, error) {
	return scanPackage(r.db.sql.QueryRow(`SELECT `+packageColumns+` FROM packages WHERE id = ?`, id))
}

func (r *PackagesRepo) List(includeHidden bool) ([]Package, error) {
	q := `SELECT ` + packageColumns + ` FROM packages`
	if !includeHidden {
		q += ` WHERE visible = 1`
	}
	q += ` ORDER BY price_credit ASC`
	rows, err := r.db.sql.Query(q)
	if err != nil {
		return nil, fmt.Errorf("query packages: %w", err)
	}
	defer rows.Close()
	var out []Package
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []Package{}
	}
	return out, rows.Err()
}

type CreatePackageInput struct {
	Name         string
	Description  string
	QuotaKind    string
	QuotaScope   string
	QuotaAmount  int64
	PlanType     string
	WindowHours  int64
	DurationDays int64
	PriceCredit  int64
	Models       []string
	RPM          int
	Visible      bool
}

func (r *PackagesRepo) Create(in CreatePackageInput) (Package, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return Package{}, fmt.Errorf("name is required")
	}
	if in.QuotaKind == "" {
		in.QuotaKind = "token"
	}
	if in.QuotaScope == "" {
		in.QuotaScope = "lifetime"
	}
	if in.QuotaAmount <= 0 {
		return Package{}, fmt.Errorf("quota_amount must be > 0")
	}
	if in.DurationDays == 0 {
		in.DurationDays = -1
	}
	if in.PlanType == "" {
		switch in.QuotaScope {
		case "hour", "day", "week", "month":
			in.PlanType = "windowed"
		default:
			in.PlanType = "lifetime"
		}
	}
	if in.RPM <= 0 {
		in.RPM = 60
	}
	vis := 0
	if in.Visible {
		vis = 1
	}
	id := newID("pkg")
	_, err := r.db.sql.Exec(`
		INSERT INTO packages (id, name, description, quota_kind, quota_scope,
			quota_amount, plan_type, window_hours, duration_days, price_credit, allowed_models, rpm, visible, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, in.Name, nullIfEmpty(in.Description), in.QuotaKind, in.QuotaScope,
		in.QuotaAmount, in.PlanType, nullWindowHours(in.WindowHours), in.DurationDays,
		in.PriceCredit, encodeJSONList(in.Models), in.RPM, vis, Now())
	if err != nil {
		if isUniqueViolation(err) {
			return Package{}, ErrDuplicate
		}
		return Package{}, fmt.Errorf("insert package: %w", err)
	}
	return r.ByID(id)
}

func (r *PackagesRepo) Update(id string, in CreatePackageInput) (Package, error) {
	vis := 0
	if in.Visible {
		vis = 1
	}
	_, err := r.db.sql.Exec(`
		UPDATE packages SET name = ?, description = ?, quota_kind = ?, quota_scope = ?,
			quota_amount = ?, plan_type = ?, window_hours = ?, duration_days = ?, price_credit = ?, allowed_models = ?,
			rpm = ?, visible = ?
		WHERE id = ?`,
		in.Name, nullIfEmpty(in.Description), in.QuotaKind, in.QuotaScope,
		in.QuotaAmount, in.PlanType, nullWindowHours(in.WindowHours), in.DurationDays,
		in.PriceCredit, encodeJSONList(in.Models),
		in.RPM, vis, id)
	if err != nil {
		return Package{}, fmt.Errorf("update package: %w", err)
	}
	return r.ByID(id)
}

func (r *PackagesRepo) Delete(id string) error {
	result, err := r.db.sql.Exec(`DELETE FROM packages WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete package: %w", err)
	}
	return requireOneRow(result)
}

// Order mirrors one row of orders.
type Order struct {
	ID          string
	UserID      string
	PackageID   string
	KeyID       string
	Kind        string
	PriceCredit int64
	Status      string
	CreatedAt   int64
}

type OrdersRepo struct{ db *DB }

func (d *DB) Orders() *OrdersRepo { return &OrdersRepo{db: d} }

const orderColumns = `id, user_id, package_id, COALESCE(key_id,''), kind, price_credit, status, created_at`

func (r *OrdersRepo) List(limit int) ([]Order, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := r.db.sql.Query(
		`SELECT `+orderColumns+` FROM orders ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query orders: %w", err)
	}
	defer rows.Close()
	var out []Order
	for rows.Next() {
		var o Order
		if err := rows.Scan(&o.ID, &o.UserID, &o.PackageID, &o.KeyID, &o.Kind, &o.PriceCredit, &o.Status, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	if out == nil {
		out = []Order{}
	}
	return out, rows.Err()
}

func (r *OrdersRepo) Create(userID, packageID, keyID, kind string, price int64, status string) (Order, error) {
	id := newID("ord")
	now := Now()
	_, err := r.db.sql.Exec(`
		INSERT INTO orders (id, user_id, package_id, key_id, kind, price_credit, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, userID, packageID, nullIfEmpty(keyID), kind, price, status, now)
	if err != nil {
		return Order{}, fmt.Errorf("insert order: %w", err)
	}
	return Order{ID: id, UserID: userID, PackageID: packageID, KeyID: keyID, Kind: kind, PriceCredit: price, Status: status, CreatedAt: now}, nil
}
