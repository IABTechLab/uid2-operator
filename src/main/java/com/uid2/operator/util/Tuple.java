package com.uid2.operator.util;

public class Tuple {
    public static class Tuple2<T1, T2> {
        private final T1 item1;
        private final T2 item2;

        public Tuple2(T1 item1, T2 item2) {
            if (item1 == null || item2 == null) {
                throw new NullPointerException();
            }

            this.item1 = item1;
            this.item2 = item2;
        }

        public T1 getItem1() { return item1; }
        public T2 getItem2() { return item2; }

        @Override
        public int hashCode() { return item1.hashCode() ^ item2.hashCode(); }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Tuple2)) return false;
            Tuple2 pairo = (Tuple2) o;
            return this.item1.equals(pairo.item1) &&
                    this.item2.equals(pairo.item2);
        }
    }

    public static class Tuple3<T1, T2, T3> {
        private final T1 item1;
        private final T2 item2;
        private final T3 item3;

        public Tuple3(T1 item1, T2 item2, T3 item3) {
            if (item1 == null || item2 == null || item3 == null) {
                throw new NullPointerException();
            }

            this.item1 = item1;
            this.item2 = item2;
            this.item3 = item3;
        }

        public T1 getItem1() { return item1; }
        public T2 getItem2() { return item2; }
        public T3 getItem3() { return item3; }

        @Override
        public int hashCode() { return item1.hashCode() ^ item2.hashCode() ^ item3.hashCode(); }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Tuple3)) return false;
            Tuple3 tripleo = (Tuple3) o;
            return this.item1.equals(tripleo.item1) &&
                    this.item2.equals(tripleo.item2) &&
                    this.item3.equals(tripleo.item3);
        }
    }
}


